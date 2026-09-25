#![forbid(unsafe_code)]

//! The key home (ADR-0063 clause 4): where Xmip's keys come from.
//!
//! What Xmip stores of its own is sealed under a [`DataKey`], and a data key
//! is never stored as it is: a [`KeyStore`] wraps it under a
//! key-encryption key named by a [`KekName`], and only the wrapped bytes are
//! written anywhere. The key-encryption key lives in the platform's key store
//! — DPAPI on Windows, a file only the Service Identity can read on Linux,
//! the keychain on macOS — each a technology mounted beside this source. A
//! hardware module over PKCS#11 or a vault is a further technology of the
//! same trait, reserved in `architecture.toml` until one is written.
//!
//! **The sealing is here, once.** AES-256-GCM, HKDF and HMAC-SHA-256 come
//! from aws-lc-rs, the crypto `xmip-core-library-tls` already builds, and
//! [`DataKey`] is the one place the estate calls them for data at rest:
//! `xmip-core-persist` seals its records with it and the technologies that
//! hold a key-encryption key as bytes ([`Held`]) wrap with it. A technology
//! that keeps its key where the key cannot leave — a hardware module —
//! implements [`KeyStore`] itself and seals inside the module.
//!
//! **A missing key-encryption key is said, never replaced.** Wrapping
//! creates one when it is absent; unwrapping never does, because a new key
//! cannot open what the old one sealed, and inventing one would turn a lost
//! key into silently unreadable data. [`SecretError::MissingKek`] names the
//! key and the store.

// Each subject in a file of its own, and each reached at one path: the
// crate's root.
mod data_key;
mod error;
#[cfg(any(test, feature = "test-support"))]
pub mod fixture;
mod kek_holder;
mod kek_name;
mod store;

pub use data_key::DataKey;
pub use error::SecretError;
pub use kek_holder::{Held, KekHolder};
pub use kek_name::KekName;
pub use store::Store;

/// A key store: wraps and unwraps a data key under a named key-encryption
/// key, and says which store it is.
pub trait KeyStore: Send + Sync {
    /// Which store this is and where it keeps its keys, for a record or a
    /// message; never read for meaning (ADR-0063, the capability decides).
    fn store(&self) -> Store;

    /// Wrap `key` under the key-encryption key `kek`, creating that key
    /// first if the store does not hold it.
    ///
    /// # Errors
    ///
    /// When the store cannot be reached, refuses to create the key, or
    /// holds one it will not trust ([`SecretError::Exposed`]).
    fn wrap(&self, kek: &KekName, key: &DataKey) -> Result<Vec<u8>, SecretError>;

    /// Unwrap what [`KeyStore::wrap`] made under `kek`.
    ///
    /// # Errors
    ///
    /// [`SecretError::MissingKek`] when the store does not hold `kek` — it
    /// is never created here — and [`SecretError::Refused`] when the
    /// wrapped bytes fail their authentication tag.
    fn unwrap(&self, kek: &KekName, wrapped: &[u8]) -> Result<DataKey, SecretError>;
}
