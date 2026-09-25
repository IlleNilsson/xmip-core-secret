//! Why a key could not be had, or a sealed value could not be opened.

use std::error::Error;
use std::fmt;

/// What went wrong in the key home, in words an operator can act on.
#[derive(Debug, Eq, PartialEq)]
pub enum SecretError {
    /// The store does not hold the key-encryption key asked for. Never
    /// answered by creating one: a new key cannot open what the old one
    /// sealed (ADR-0063, Consequences).
    MissingKek { name: String, store: String },
    /// A sealed value failed its authentication tag: it was altered, it was
    /// sealed under another key, or it was sealed for another place.
    Refused { reason: String },
    /// The store holds the key somewhere others can read it, and so will not
    /// use it.
    Exposed { what: String },
    /// Something asked for is not well formed: a key's name, a key's length.
    Invalid { what: String },
    /// The store could not be reached or answered with an error of its own.
    Store { reason: String },
}

impl SecretError {
    /// A store's own failure, in its own words.
    pub fn store(cause: impl fmt::Display) -> Self {
        Self::Store {
            reason: cause.to_string(),
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKek { name, store } => write!(
                f,
                "key-encryption key '{name}' is not in {store}; it is never created on \
                 unwrap, because a new key cannot open what the old one sealed"
            ),
            Self::Refused { reason } => write!(f, "refused: {reason}"),
            Self::Exposed { what } => write!(f, "not used, readable by others: {what}"),
            Self::Invalid { what } => write!(f, "invalid: {what}"),
            Self::Store { reason } => write!(f, "key store: {reason}"),
        }
    }
}

impl Error for SecretError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_key_names_the_key_and_the_store() {
        let text = SecretError::MissingKek {
            name: "runtime".to_string(),
            store: "file at /k".to_string(),
        }
        .to_string();
        assert!(text.contains("'runtime'"), "{text}");
        assert!(text.contains("file at /k"), "{text}");
    }
}
