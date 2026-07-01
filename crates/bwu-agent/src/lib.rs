#![forbid(unsafe_code)]
//! M1 skeleton for the optional `bwu-agent` process.

use std::fmt::Write as _;

use bwu_core::{
    NotImplemented,
    command::{AGENT_COMMANDS, is_planned_agent_operation, wants_help},
    namespace::{AGENT_DEFAULT_TIMEOUT_SECONDS, AGENT_SOCKET_NAME, RUNTIME_DIR_NAME},
};

const NOT_IMPLEMENTED_EXIT: i32 = 2;
const USAGE_EXIT: i32 = 64;

/// Captured command result for the agent binary entrypoint and tests.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AgentOutcome {
    /// Process exit code.
    pub code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl AgentOutcome {
    fn success(stdout: String) -> Self {
        Self {
            code: 0,
            stdout,
            stderr: String::new(),
        }
    }

    fn error(code: i32, stderr: String) -> Self {
        Self {
            code,
            stdout: String::new(),
            stderr,
        }
    }
}

/// Runs the `bwu-agent` command-line skeleton.
#[must_use]
pub fn run(args: impl IntoIterator<Item = String>) -> AgentOutcome {
    let args: Vec<String> = args.into_iter().collect();

    if wants_help(&args) {
        return AgentOutcome::success(help_text());
    }

    if is_planned_agent_operation(&args) {
        return AgentOutcome::error(
            NOT_IMPLEMENTED_EXIT,
            format!("{}\n", NotImplemented::agent(args.join(" "))),
        );
    }

    AgentOutcome::error(
        USAGE_EXIT,
        "Unknown command. Run `bwu-agent --help`.\n".to_string(),
    )
}

/// Builds the current agent help screen.
#[must_use]
pub fn help_text() -> String {
    let mut help = String::new();
    writeln!(
        help,
        "bwu-agent - optional local Unix socket agent (M1 skeleton)"
    )
    .expect("writing to String cannot fail");
    writeln!(help).expect("writing to String cannot fail");
    writeln!(help, "Usage: bwu-agent <command> [options]").expect("writing to String cannot fail");
    writeln!(help).expect("writing to String cannot fail");
    writeln!(
        help,
        "Socket: local Unix socket `{AGENT_SOCKET_NAME}` under the `{RUNTIME_DIR_NAME}` runtime directory."
    )
    .expect("writing to String cannot fail");
    writeln!(
        help,
        "Default unlock timeout: {AGENT_DEFAULT_TIMEOUT_SECONDS} seconds."
    )
    .expect("writing to String cannot fail");
    writeln!(help).expect("writing to String cannot fail");
    writeln!(help, "Planned commands:").expect("writing to String cannot fail");

    for operation in AGENT_COMMANDS[0].operations {
        writeln!(help, "  {operation}").expect("writing to String cannot fail");
    }

    help
}
