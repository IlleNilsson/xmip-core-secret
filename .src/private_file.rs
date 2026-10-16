//! A private file: one only the user this process runs as can read, kept so
//! that a crash at any step leaves either the file as it was or the file
//! whole, never half of one. Every key and identity the estate keeps on disk
//! is written here, once: the key-encryption keys of the `file` and `dpapi`
//! stores, a node's certificate and key, the cluster's authority, an ACME
//! account key and a person's operator key.
//!
//! **Owner-only before the first byte.** The bytes go to a file created for
//! them beside the one they become, and its access is set as it is created:
//! on Unix mode `0600`, a directory `0700`; on Windows an access list
//! granting the user this process runs as and `SYSTEM` full control and no
//! one else, protected from what the folder above passes down
//! ([`owner_only`]). A directory is created owner-only where it is absent;
//! one already there keeps what it has.
//!
//! **Synced, then switched.** The file is synced to the disk before it takes
//! its place — by a rename for [`replace`], by a link that refuses a file
//! already there for [`create`] — and on Unix the directory is synced after,
//! so the switch itself survives a crash. Windows journals the rename.
//!
//! **A crash's leftover is swept.** A file written and never switched has a
//! name of one exact shape, `.<name>.<16 hex>.new`; whoever opens a folder
//! of private files removes those first ([`sweep`]), and nothing else.
//!
//! **What is not secret is kept the same way.** A chain or the anchors a
//! surface trusts are replaced whole and synced by [`replace_readable`],
//! readable as their directory lets.

#[cfg(windows)]
mod dacl;

use std::fs::{self, File};
use std::io::{Error, ErrorKind, Result, Write};
use std::path::{Path, PathBuf};

#[cfg(windows)]
pub use dacl::{described, owner_only};

/// The directory at `path` and those above it, each created owner-only
/// where it is absent; one already there is left as it is.
///
/// # Errors
///
/// Where a directory cannot be created or its access set.
pub fn directory(path: &Path) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(windows)]
    {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            directory(parent)?;
        }
        match fs::create_dir(path) {
            Ok(()) => dacl::protect_directory(path),
            Err(failure) if failure.kind() == ErrorKind::AlreadyExists => Ok(()),
            Err(failure) => Err(failure),
        }
    }
}

/// `bytes` kept privately at `path`, in place of what was there.
///
/// # Errors
///
/// Where the directory, the file or the rename fails; what was at `path`
/// is then as it was.
pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    switched(path, &written(path, bytes, Access::Owner)?)
}

/// `bytes` kept whole at `path`, in place of what was there, as [`replace`]
/// keeps them — written beside it, synced, renamed, the directory synced —
/// but readable as its directory lets: a certificate chain or the anchors a
/// surface trusts, which are not secret. A directory it creates is
/// created as any other.
///
/// # Errors
///
/// Where the directory, the file or the rename fails; what was at `path`
/// is then as it was.
pub fn replace_readable(path: &Path, bytes: &[u8]) -> Result<()> {
    switched(path, &written(path, bytes, Access::Inherited)?)
}

/// What was written at `fresh` renamed over `path`, its directory synced.
fn switched(path: &Path, fresh: &Path) -> Result<()> {
    fs::rename(fresh, path).inspect_err(|_| {
        let _ = fs::remove_file(fresh);
    })?;
    synced(parent(path))
}

/// Every file a crash left in `folder` between writing and switching — a
/// name of exactly the shape this module gives one, `.<name>.<16 hex>.new`
/// — removed. Whoever opens a folder of private files calls it first; a
/// missing folder holds none.
///
/// # Errors
///
/// Where the folder cannot be listed or a leftover cannot be removed.
pub fn sweep(folder: &Path) -> Result<()> {
    let entries = match fs::read_dir(folder) {
        Ok(entries) => entries,
        Err(failure) if failure.kind() == ErrorKind::NotFound => return Ok(()),
        Err(failure) => return Err(failure),
    };
    for entry in entries {
        let entry = entry?;
        let leftover = entry.file_name().to_str().is_some_and(is_leftover);
        if leftover && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// The digits of the random part of a written file's name.
const NONCE_DIGITS: usize = 16;

/// Whether `name` is the shape [`written`] gives: a dot, a name, a dot,
/// sixteen lower-case hex digits, `.new`.
fn is_leftover(name: &str) -> bool {
    let Some(inner) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".new"))
    else {
        return false;
    };
    let Some((kept, nonce)) = inner.rsplit_once('.') else {
        return false;
    };
    !kept.is_empty()
        && nonce.len() == NONCE_DIGITS
        && nonce
            .bytes()
            .all(|digit| digit.is_ascii_digit() || (b'a'..=b'f').contains(&digit))
}

/// The access a written file is created with.
#[derive(Clone, Copy)]
enum Access {
    /// The user this process runs as, alone.
    Owner,
    /// What the directory gives what is made in it.
    Inherited,
}

/// `bytes` kept privately at `path`, never over a file already there: a
/// key that replaced another is everything the other sealed, lost.
///
/// # Errors
///
/// [`ErrorKind::AlreadyExists`] where `path` is there; or the directory,
/// the file or the link fails, and nothing is at `path`.
pub fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    let fresh = written(path, bytes, Access::Owner)?;
    let linked = fs::hard_link(&fresh, path);
    let _ = fs::remove_file(&fresh);
    linked?;
    synced(parent(path))
}

/// `bytes` in a new file beside `path` with `access`, synced, its name a
/// random one that cannot be the name of a file kept here: the first step
/// of [`replace`] and [`create`], which a crash may leave, nothing reads and
/// [`sweep`] removes.
fn written(path: &Path, bytes: &[u8], access: Access) -> Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("{} names no file", path.display()),
        )
    })?;
    let folder = parent(path);
    let nonce = codec::hex::encode(&codec::random::array::<{ NONCE_DIGITS / 2 }>());
    let fresh = folder.join(format!(".{}.{nonce}.new", name.to_string_lossy()));
    let mut file = match access {
        Access::Owner => {
            directory(folder)?;
            opened(&fresh)?
        }
        Access::Inherited => {
            fs::create_dir_all(folder)?;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&fresh)?
        }
    };
    let kept = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    kept.inspect_err(|_| {
        let _ = fs::remove_file(&fresh);
    })?;
    Ok(fresh)
}

/// A new file at `path`, owner-only as it is created.
fn opened(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        dacl::create(path)
    }
}

/// The directory `path` is in; the current one for a bare name.
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// The directory at `path` synced, so a rename or link inside it survives
/// a crash. On Unix; Windows journals both and has no directory to sync.
///
/// # Errors
///
/// Where the directory cannot be opened or synced.
pub fn synced(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place(test: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("xmip-secret-private-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    /// The access `path` has, as the platform says it.
    fn access(path: &Path) -> String {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            format!("{:o}", fs::metadata(path).expect("metadata").mode() & 0o777)
        }
        #[cfg(windows)]
        {
            described(path).expect("described")
        }
    }

    fn owner(directory: bool) -> String {
        #[cfg(unix)]
        {
            (if directory { "700" } else { "600" }).to_string()
        }
        #[cfg(windows)]
        {
            owner_only(directory).expect("owner only")
        }
    }

    #[test]
    fn a_private_file_and_its_directory_are_the_owners_alone() {
        let base = place("access");
        let path = base.join("inner").join("key.pem");
        replace(&path, b"secret").expect("kept");
        assert_eq!(fs::read(&path).expect("read"), b"secret");
        assert_eq!(access(&path), owner(false));
        assert_eq!(access(path.parent().expect("parent")), owner(true));
        assert_eq!(access(&base), owner(true));
        create(&base.join("account.key"), b"made").expect("created");
        assert_eq!(access(&base.join("account.key")), owner(false));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_file_is_replaced_whole_and_created_never_over_one() {
        let base = place("replace");
        let path = base.join("key.pem");
        replace(&path, b"first").expect("kept");
        replace(&path, b"second").expect("replaced");
        assert_eq!(fs::read(&path).expect("read"), b"second");
        let refused = create(&path, b"third").expect_err("there already");
        assert_eq!(refused.kind(), ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).expect("read"), b"second");
        let left: Vec<_> = fs::read_dir(&base).expect("listed").collect();
        assert_eq!(left.len(), 1, "no written file is left beside it");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_crash_after_the_bytes_are_written_leaves_the_file_as_it_was() {
        let base = place("crash");
        let path = base.join("key.pem");
        replace(&path, b"old").expect("kept");
        let fresh = written(&path, b"new", Access::Owner).expect("written");
        assert_eq!(fs::read(&path).expect("read"), b"old");
        assert_eq!(access(&fresh), owner(false), "owner-only before a byte");
        replace(&path, b"newer").expect("replaced after the crash");
        assert_eq!(fs::read(&path).expect("read"), b"newer");

        // The next to open the folder sweeps what the crash left, and only that.
        let lookalikes = [
            ".key.pem.0123456789ABCDEF.new",
            ".key.pem.0123456789abcde.new",
            "..0123456789abcdef.new",
            "key.pem.0123456789abcdef.new",
            ".key.pem.0123456789abcdef.old",
        ];
        for name in lookalikes {
            fs::write(base.join(name), b"kept").expect("written");
        }
        assert!(fresh.exists());
        sweep(&base).expect("swept");
        assert!(!fresh.exists(), "the leftover is removed");
        for name in lookalikes {
            assert!(base.join(name).exists(), "{name} is not a leftover");
        }
        assert_eq!(fs::read(&path).expect("read"), b"newer");
        sweep(&base.join("absent")).expect("a missing folder holds none");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_readable_file_is_replaced_whole_and_synced() {
        let base = place("readable");
        let path = base.join("chain.pem");
        replace_readable(&path, b"first").expect("kept");
        replace_readable(&path, b"second").expect("replaced");
        assert_eq!(fs::read(&path).expect("read"), b"second");
        let left: Vec<_> = fs::read_dir(&base).expect("listed").collect();
        assert_eq!(left.len(), 1, "no written file is left beside it");
        assert_ne!(access(&path), owner(false), "readable as the folder lets");
        let _ = fs::remove_dir_all(&base);
    }
}
