//! The name a key-encryption key is kept under.

use crate::SecretError;
use std::fmt;

/// The longest name a key-encryption key may have.
const LONGEST: usize = 64;

/// The name of a key-encryption key: letters, digits, `.`, `_` and `-`,
/// one to sixty-four of them, not starting with `.`.
///
/// Narrow on purpose. Every technology turns it into something of its own —
/// a file name, a keychain account, a PKCS#11 label — and a name that is
/// safe in all of them needs no escaping in any.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KekName(String);

impl KekName {
    /// A key-encryption key's name, checked.
    ///
    /// # Errors
    ///
    /// [`SecretError::Invalid`] for an empty name, one over sixty-four
    /// characters, one starting with `.`, or one with any other character.
    pub fn new(name: &str) -> Result<Self, SecretError> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        if name.is_empty()
            || name.len() > LONGEST
            || name.starts_with('.')
            || !name.chars().all(allowed)
        {
            return Err(SecretError::Invalid {
                what: format!(
                    "key-encryption key name '{name}': one to {LONGEST} letters, digits, \
                     '.', '_' or '-', not starting with '.'"
                ),
            });
        }
        Ok(Self(name.to_string()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KekName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_name_is_taken() {
        assert_eq!(
            KekName::new("runtime-store.1").expect("valid").as_str(),
            "runtime-store.1"
        );
    }

    #[test]
    fn a_name_that_is_not_safe_everywhere_is_refused() {
        for name in ["", ".hidden", "a/b", "a b", "..", &"k".repeat(65)] {
            assert!(
                matches!(KekName::new(name), Err(SecretError::Invalid { .. })),
                "{name:?} should be refused"
            );
        }
    }
}
