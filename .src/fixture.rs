//! A key-encryption key holder in memory, for tests only.
//!
//! What uses a key store — persist and its engines — proves itself against
//! this rather than the machine's own key store, so its tests neither need
//! nor touch one. Behind the `test-support` feature, which a crate enables
//! from its dev-dependencies alone.

use crate::{KekHolder, KekName, SecretError, Store};
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Key-encryption keys in a map, gone when it is dropped.
#[derive(Default)]
pub struct Memory {
    keys: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl KekHolder for Memory {
    fn store(&self) -> Store {
        Store {
            technology: "memory",
            place: "this process, for tests".to_string(),
        }
    }

    fn read(&self, name: &KekName) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| SecretError::store("poisoned"))?;
        Ok(keys.get(name.as_str()).cloned())
    }

    fn create(&self, name: &KekName, material: &[u8]) -> Result<(), SecretError> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| SecretError::store("poisoned"))?;
        if keys.contains_key(name.as_str()) {
            return Err(SecretError::store(format!("'{name}' exists")));
        }
        keys.insert(name.to_string(), Zeroizing::new(material.to_vec()));
        Ok(())
    }
}
