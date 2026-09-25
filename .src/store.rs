//! Which key store a key came from, said rather than read.

use std::fmt;

/// A key store's account of itself: the technology, and where it keeps
/// its keys.
///
/// For a record, an audit line or a message to an operator. Nothing at run
/// time decides anything from it; the store that was configured is the one
/// that answers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Store {
    /// The technology, as `architecture.toml` names it: `dpapi`, `file`,
    /// `keychain`.
    pub technology: &'static str,
    /// Where it keeps its keys: a directory, a keychain service name.
    pub place: String,
}

impl fmt::Display for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.technology, self.place)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_says_its_technology_and_its_place() {
        let store = Store {
            technology: "file",
            place: "/var/lib/xmip/key".to_string(),
        };
        assert_eq!(store.to_string(), "file at /var/lib/xmip/key");
    }
}
