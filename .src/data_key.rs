//! A data key, and the one place Xmip seals data at rest with it.

use crate::SecretError;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::{hkdf, hmac, rand};
use std::fmt;
use zeroize::Zeroizing;

/// The length of every key here, in bytes: AES-256 and HMAC-SHA-256 alike.
pub(crate) const KEY_LEN: usize = 32;

/// The length of the authentication tag AES-256-GCM appends.
const TAG_LEN: usize = 16;

/// A 256-bit data key: what seals, derives and hashes.
///
/// It is never written as it is. A [`crate::KeyStore`] wraps it, and the
/// wrapped bytes are what a store keeps. Its bytes are overwritten when it
/// is dropped, and `Debug` does not print them.
pub struct DataKey {
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

/// HKDF's output length, which aws-lc-rs asks for as a type.
struct KeyLength;

impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        KEY_LEN
    }
}

impl DataKey {
    /// A fresh key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// [`SecretError::Store`] when the random source fails.
    pub fn generate() -> Result<Self, SecretError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        rand::fill(bytes.as_mut()).map_err(|_| SecretError::store("no random bytes"))?;
        Ok(Self { bytes })
    }

    /// A key from bytes a store kept: exactly thirty-two of them.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, SecretError> {
        let bytes: [u8; KEY_LEN] = bytes.try_into().map_err(|_| SecretError::Invalid {
            what: format!("a key of {} bytes, not {KEY_LEN}", bytes.len()),
        })?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// The key's bytes, for a store that holds a key-encryption key as
    /// bytes. Never leaves the crate.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// A second key for another purpose, derived from this one by
    /// HKDF-SHA-256 with `purpose` as its info, so one wrapped key serves
    /// several and no two purposes share a key.
    ///
    /// # Errors
    ///
    /// [`SecretError::Store`] if HKDF refuses the length, which it does not
    /// for thirty-two bytes.
    pub fn derive(&self, purpose: &[u8]) -> Result<Self, SecretError> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        hkdf::Salt::new(hkdf::HKDF_SHA256, &[])
            .extract(self.bytes())
            .expand(&[purpose], KeyLength)
            .and_then(|okm| okm.fill(bytes.as_mut()))
            .map_err(|_| SecretError::store("key derivation failed"))?;
        Ok(Self { bytes })
    }

    /// `plaintext` sealed by AES-256-GCM under a fresh random nonce, with
    /// `aad` authenticated beside it: the nonce, the ciphertext and the tag.
    ///
    /// `aad` is what the sealed bytes belong to — a record's key, a key's
    /// name — so bytes moved to another place fail to open there.
    ///
    /// # Errors
    ///
    /// [`SecretError::Store`] when the random source or the cipher fails.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce).map_err(|_| SecretError::store("no random bytes"))?;
        let mut sealed = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
        sealed.extend_from_slice(&nonce);
        let mut body = plaintext.to_vec();
        self.cipher()?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut body,
            )
            .map_err(|_| SecretError::store("sealing failed"))?;
        sealed.extend_from_slice(&body);
        Ok(sealed)
    }

    /// What [`DataKey::seal`] sealed with the same `aad`, authenticated.
    ///
    /// # Errors
    ///
    /// [`SecretError::Refused`] when the bytes are too short to be sealed,
    /// or fail their tag: altered, sealed under another key, or sealed for
    /// another `aad`.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SecretError> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(SecretError::Refused {
                reason: format!("{} bytes cannot be a sealed value", sealed.len()),
            });
        }
        let (nonce, body) = sealed.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| SecretError::store("nonce length"))?;
        let mut body = body.to_vec();
        let opened = self
            .cipher()?
            .open_in_place(nonce, Aad::from(aad), &mut body)
            .map_err(|_| SecretError::Refused {
                reason: "the authentication tag does not match: altered, another key, \
                         or another place"
                    .to_string(),
            })?;
        Ok(opened.to_vec())
    }

    /// HMAC-SHA-256 of `data` under this key: a name that can be looked up
    /// again and does not say what it names.
    #[must_use]
    pub fn keyed_hash(&self, data: &[u8]) -> [u8; KEY_LEN] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.bytes());
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(hmac::sign(&key, data).as_ref());
        out
    }

    fn cipher(&self) -> Result<LessSafeKey, SecretError> {
        UnboundKey::new(&AES_256_GCM, self.bytes())
            .map(LessSafeKey::new)
            .map_err(|_| SecretError::store("AES-256-GCM refused the key"))
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_sealed_opens_with_the_same_key_and_place() {
        let key = DataKey::generate().expect("key");
        let sealed = key.seal(b"orders/4711", b"payload").expect("sealed");
        assert_eq!(
            key.open(b"orders/4711", &sealed).expect("opened"),
            b"payload"
        );
    }

    #[test]
    fn every_seal_takes_a_fresh_nonce() {
        let key = DataKey::generate().expect("key");
        let first = key.seal(b"a", b"same").expect("sealed");
        let second = key.seal(b"a", b"same").expect("sealed");
        assert_ne!(first, second);
    }

    #[test]
    fn an_altered_byte_is_refused() {
        let key = DataKey::generate().expect("key");
        let mut sealed = key.seal(b"a", b"payload").expect("sealed");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(matches!(
            key.open(b"a", &sealed),
            Err(SecretError::Refused { .. })
        ));
    }

    #[test]
    fn another_key_or_another_place_is_refused() {
        let key = DataKey::generate().expect("key");
        let sealed = key.seal(b"a", b"payload").expect("sealed");
        let other = DataKey::generate().expect("key");
        assert!(matches!(
            other.open(b"a", &sealed),
            Err(SecretError::Refused { .. })
        ));
        assert!(matches!(
            key.open(b"b", &sealed),
            Err(SecretError::Refused { .. })
        ));
        assert!(matches!(
            key.open(b"a", &sealed[..10]),
            Err(SecretError::Refused { .. })
        ));
    }

    #[test]
    fn derived_keys_differ_by_purpose_and_repeat_for_the_same_one() {
        let key = DataKey::generate().expect("key");
        let a = key.derive(b"record").expect("derived");
        let b = key.derive(b"lookup").expect("derived");
        assert_ne!(a.bytes(), b.bytes());
        assert_eq!(a.bytes(), key.derive(b"record").expect("derived").bytes());
    }

    #[test]
    fn a_keyed_hash_repeats_and_depends_on_the_key() {
        let key = DataKey::generate().expect("key");
        assert_eq!(key.keyed_hash(b"orders"), key.keyed_hash(b"orders"));
        let other = DataKey::generate().expect("key");
        assert_ne!(key.keyed_hash(b"orders"), other.keyed_hash(b"orders"));
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused_and_debug_hides_the_bytes() {
        assert!(matches!(
            DataKey::from_bytes(&[0; 16]),
            Err(SecretError::Invalid { .. })
        ));
        let key = DataKey::generate().expect("key");
        assert_eq!(format!("{key:?}"), "DataKey(..)");
    }
}
