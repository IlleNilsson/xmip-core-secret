//! A key store whose key-encryption key is kept as bytes, and the wrapping
//! every such store shares.

use crate::data_key::KEY_LEN;
use crate::{DataKey, KekName, KeyStore, SecretError, Store};
use zeroize::Zeroizing;

/// What holds a key-encryption key as bytes: DPAPI, a file, the keychain.
///
/// It keeps and gives back thirty-two bytes and nothing more; the wrapping
/// is [`Held`]'s, once, so no technology carries its own copy of it.
pub trait KekHolder: Send + Sync {
    /// Which store this is and where it keeps its keys.
    fn store(&self) -> Store;

    /// The key-encryption key `name`, or `None` when it is not held.
    ///
    /// # Errors
    ///
    /// [`SecretError::Exposed`] when the key is held where others can read
    /// it, and [`SecretError::Store`] when the store cannot be read.
    fn read(&self, name: &KekName) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError>;

    /// Keep `material` as the key-encryption key `name`. Never replaces a
    /// key already held: a replaced key is every value it sealed, lost.
    ///
    /// # Errors
    ///
    /// When the key already exists, or the store cannot be written.
    fn create(&self, name: &KekName, material: &[u8]) -> Result<(), SecretError>;
}

/// A [`KeyStore`] over a [`KekHolder`]: the key-encryption key is read from
/// the holder, and a data key is sealed under it with its name as the place.
pub struct Held<H> {
    holder: H,
}

impl<H: KekHolder> Held<H> {
    /// A key store over `holder`.
    pub fn new(holder: H) -> Self {
        Self { holder }
    }

    /// The key-encryption key `name`, created when it is absent.
    fn kek_or_create(&self, name: &KekName) -> Result<DataKey, SecretError> {
        if let Some(bytes) = self.holder.read(name)? {
            return DataKey::from_bytes(&bytes);
        }
        let fresh = DataKey::generate()?;
        match self.holder.create(name, fresh.bytes()) {
            Ok(()) => Ok(fresh),
            // Another process created it between the read and the create:
            // its key is the key, and this one is dropped unused.
            Err(refused) => match self.holder.read(name)? {
                Some(bytes) => DataKey::from_bytes(&bytes),
                None => Err(refused),
            },
        }
    }
}

/// What a wrapped key is sealed for: its key-encryption key's name, so a
/// wrapped key moved under another name fails to open.
fn place(name: &KekName) -> Vec<u8> {
    [
        b"xmip-core-secret/wrap/".as_slice(),
        name.as_str().as_bytes(),
    ]
    .concat()
}

impl<H: KekHolder> KeyStore for Held<H> {
    fn store(&self) -> Store {
        self.holder.store()
    }

    fn wrap(&self, kek: &KekName, key: &DataKey) -> Result<Vec<u8>, SecretError> {
        self.kek_or_create(kek)?.seal(&place(kek), key.bytes())
    }

    fn unwrap(&self, kek: &KekName, wrapped: &[u8]) -> Result<DataKey, SecretError> {
        let Some(bytes) = self.holder.read(kek)? else {
            return Err(SecretError::MissingKek {
                name: kek.to_string(),
                store: self.holder.store().to_string(),
            });
        };
        let opened = Zeroizing::new(DataKey::from_bytes(&bytes)?.open(&place(kek), wrapped)?);
        if opened.len() != KEY_LEN {
            return Err(SecretError::Invalid {
                what: format!("a wrapped key of {} bytes", opened.len()),
            });
        }
        DataKey::from_bytes(&opened)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::Memory;

    fn name(text: &str) -> KekName {
        KekName::new(text).expect("name")
    }

    #[test]
    fn a_wrapped_key_unwraps_to_the_same_key() {
        let store = Held::new(Memory::default());
        let key = DataKey::generate().expect("key");
        let wrapped = store.wrap(&name("runtime"), &key).expect("wrapped");
        let back = store.unwrap(&name("runtime"), &wrapped).expect("unwrapped");
        assert_eq!(back.bytes(), key.bytes());
        assert!(!wrapped.windows(KEY_LEN).any(|w| w == key.bytes()));
    }

    #[test]
    fn wrapping_creates_the_key_once_and_reuses_it() {
        let store = Held::new(Memory::default());
        let key = DataKey::generate().expect("key");
        let first = store.wrap(&name("runtime"), &key).expect("wrapped");
        let second = store.wrap(&name("runtime"), &key).expect("wrapped");
        assert!(store.unwrap(&name("runtime"), &first).is_ok());
        assert!(store.unwrap(&name("runtime"), &second).is_ok());
    }

    #[test]
    fn a_missing_key_is_said_and_not_created() {
        let store = Held::new(Memory::default());
        let refused = store.unwrap(&name("absent"), &[0; 60]);
        assert!(matches!(refused, Err(SecretError::MissingKek { .. })));
        assert!(matches!(
            store.unwrap(&name("absent"), &[0; 60]),
            Err(SecretError::MissingKek { .. })
        ));
    }

    #[test]
    fn a_key_wrapped_under_one_name_does_not_open_under_another() {
        let store = Held::new(Memory::default());
        let key = DataKey::generate().expect("key");
        let wrapped = store.wrap(&name("one"), &key).expect("wrapped");
        store.wrap(&name("two"), &key).expect("creates two");
        assert!(matches!(
            store.unwrap(&name("two"), &wrapped),
            Err(SecretError::Refused { .. })
        ));
    }
}
