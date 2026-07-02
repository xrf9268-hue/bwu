#![forbid(unsafe_code)]
//! Shared primitives for the `bwu` workspace.
//!
//! This crate contains command metadata, redaction/path helpers, and the
//! isolated Bitwarden-compatible crypto core. It intentionally does not contain
//! a Bitwarden network client, persistent vault cache, or passkey signing.

pub mod command;
pub mod crypto;
pub mod error;
pub mod namespace;
pub mod paths;
pub mod redaction;

pub use command::{AGENT_COMMANDS, BWU_COMMANDS, CommandGroup};
pub use error::{M1_BOUNDARY, NotImplemented};
pub use redaction::SecretString;
