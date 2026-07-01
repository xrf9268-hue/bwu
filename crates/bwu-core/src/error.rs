//! Redacted skeleton errors shared by binaries.

use std::fmt;

/// The security boundary for all M1 executable operations.
pub const M1_BOUNDARY: &str =
    "M1 skeleton only: no network, crypto, or vault cache implementation exists yet";

/// Error returned for command groups that are planned but intentionally absent.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NotImplemented {
    component: &'static str,
    operation: String,
    boundary: &'static str,
}

impl NotImplemented {
    /// Creates a redacted not-implemented error.
    #[must_use]
    pub fn new(component: &'static str, operation: impl Into<String>) -> Self {
        Self {
            component,
            operation: operation.into(),
            boundary: M1_BOUNDARY,
        }
    }

    /// Creates a redacted agent-specific not-implemented error.
    #[must_use]
    pub fn agent(operation: impl Into<String>) -> Self {
        Self {
            component: "bwu-agent",
            operation: operation.into(),
            boundary: "Unix socket agent is not implemented in the M1 skeleton",
        }
    }
}

impl fmt::Display for NotImplemented {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} operation {:?} is not implemented. {}.",
            self.component, self.operation, self.boundary
        )
    }
}

impl std::error::Error for NotImplemented {}
