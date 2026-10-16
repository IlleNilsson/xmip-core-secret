//! A directory of key-encryption keys, one file each: the file rules every
//! store that keeps its keys as files shares, said once.
//!
//! A key named `name` is `<directory>/<name>.kek`. A new key is a private
//! file ([`crate::private_file::create`]) — owner-only, synced, and never
//! over one already there, because a replaced key is every value it sealed,
//! lost ([`crate::KekHolder::create`]). A failure names the file and says
//! what the operating system said. What a store adds — bytes it seals first,
//! checks before it reads — stays the store's.

use std::io::Error;
use std::path::{Path, PathBuf};

use crate::{KekName, SecretError, private_file};

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

    /// The directory, created owner-only where it is absent
    /// ([`private_file::directory`]); one already there keeps what it has,
    /// and loses what a crash left between writing a key and naming it
    /// ([`private_file::sweep`]).
    ///
    /// # Errors
    ///
    /// It could not be created or swept: [`SecretError::Store`], naming it.
    pub fn create_directory(&self) -> Result<(), SecretError> {
        private_file::directory(&self.directory)
            .and_then(|()| private_file::sweep(&self.directory))
            .map_err(|error| Self::failed(&self.directory, &error))
    }

    /// Keep `bytes` as the key `name`, a private file created for it
    /// ([`private_file::create`]).
    ///
    /// # Errors
    ///
    /// The file already exists, or it could not be created, written or
    /// synced: [`SecretError::Store`], naming it.
    pub fn create(&self, name: &KekName, bytes: &[u8]) -> Result<(), SecretError> {
        let path = self.path(name);
        private_file::create(&path, bytes).map_err(|error| Self::failed(&path, &error))
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
        let keys = KeyDirectory::new(&directory);
        keys.create_directory().expect("made");
        let name = KekName::new("runtime").expect("a name");

        assert_eq!(keys.path(&name), directory.join("runtime.kek"));
        keys.create(&name, &[1; 32]).expect("kept");
        let again = keys.create(&name, &[2; 32]);
        assert!(matches!(again, Err(SecretError::Store { .. })), "{again:?}");
        assert_eq!(std::fs::read(keys.path(&name)).expect("read"), [1; 32]);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
