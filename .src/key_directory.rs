//! A directory of key-encryption keys, one file each: the file rules every
//! store that keeps its keys as files shares, said once.
//!
//! A key named `name` is `<directory>/<name>.kek`. A new key is written to a
//! file created for it — never over one already there, because a replaced key
//! is every value it sealed, lost ([`crate::KekHolder::create`]) — and synced
//! before the store says it is kept. A failure names the file and says what
//! the operating system said. What a store adds — permissions it sets, bytes
//! it seals first, checks before it reads — stays the store's.

use std::fs::OpenOptions;
use std::io::{Error, Write};
use std::path::{Path, PathBuf};

use crate::{KekName, SecretError};

/// Where a store keeps its key files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyDirectory {
    directory: PathBuf,
}

impl KeyDirectory {
    /// Key files in `directory`.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// The directory itself.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The file the key `name` is kept in.
    #[must_use]
    pub fn path(&self, name: &KekName) -> PathBuf {
        self.directory.join(format!("{name}.kek"))
    }

    /// Keep `bytes` as the key `name` in a file created for it, opened with
    /// `options` as the store sets them — a mode, say — and synced.
    ///
    /// # Errors
    ///
    /// The file already exists, or it could not be created, written or
    /// synced: [`SecretError::Store`], naming it.
    pub fn create_new(
        &self,
        name: &KekName,
        bytes: &[u8],
        options: &mut OpenOptions,
    ) -> Result<(), SecretError> {
        let path = self.path(name);
        let mut file = options
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| Self::failed(&path, &error))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| Self::failed(&path, &error))
    }

    /// What the operating system said about `path`, as the store's failure.
    #[must_use]
    pub fn failed(path: &Path, error: &Error) -> SecretError {
        SecretError::store(format!("{}: {error}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_its_name_dot_kek_and_is_never_written_over() {
        let directory =
            std::env::temp_dir().join(format!("xmip-secret-key-directory-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("made");
        let keys = KeyDirectory::new(&directory);
        let name = KekName::new("runtime").expect("a name");

        assert_eq!(keys.path(&name), directory.join("runtime.kek"));
        keys.create_new(&name, &[1; 32], &mut OpenOptions::new())
            .expect("kept");
        let again = keys.create_new(&name, &[2; 32], &mut OpenOptions::new());
        assert!(matches!(again, Err(SecretError::Store { .. })), "{again:?}");
        assert_eq!(std::fs::read(keys.path(&name)).expect("read"), [1; 32]);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
