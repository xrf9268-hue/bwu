#![forbid(unsafe_code)]
//! Shared M1 skeleton primitives for the `bwu` workspace.
//!
//! This crate intentionally contains no cryptography, persistent vault cache,
//! or passkey implementation.

pub mod api;
pub mod command;
pub mod error;
pub mod namespace;
pub mod paths;
pub mod redaction;

pub use command::{AGENT_COMMANDS, BWU_COMMANDS, CommandGroup};
pub use error::{M1_BOUNDARY, NotImplemented};
pub use redaction::SecretString;
