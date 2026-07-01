//! Redaction primitives for values that must not appear in logs or snapshots.

use std::fmt;

use zeroize::Zeroize;

/// Stable marker used for redacted secret formatting.
pub const REDACTED: &str = "[REDACTED]";

/// Owned secret string whose formatting implementations never reveal the value.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretString {
    value: String,
}

impl SecretString {
    /// Wraps a synthetic or real secret value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Borrows the wrapped secret for code paths that intentionally need it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.value
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(REDACTED)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretString")
            .field(&REDACTED)
            .finish()
    }
}
