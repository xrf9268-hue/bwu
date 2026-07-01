#![forbid(unsafe_code)]
//! M1 command-line skeleton for `bwu`.

use std::fmt::Write as _;

use bwu_core::{BWU_COMMANDS, M1_BOUNDARY, NotImplemented};

const NOT_IMPLEMENTED_EXIT: i32 = 2;
const USAGE_EXIT: i32 = 64;

/// Captured command result for the binary entrypoint and tests.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommandOutcome {
    /// Process exit code.
    pub code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl CommandOutcome {
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

/// Runs the `bwu` command-line skeleton.
#[must_use]
pub fn run(args: impl IntoIterator<Item = String>) -> CommandOutcome {
    let args: Vec<String> = args.into_iter().collect();

    if bwu_core::command::wants_help(&args) {
        return CommandOutcome::success(help_text());
    }

    if bwu_core::command::is_planned_bwu_group(&args) {
        let operation = args.join(" ");
        return CommandOutcome::error(
            NOT_IMPLEMENTED_EXIT,
            format!("{}\n", NotImplemented::new("bwu", operation)),
        );
    }

    CommandOutcome::error(
        USAGE_EXIT,
        format!("Unknown command. Run `bwu --help`.\n{M1_BOUNDARY}.\n"),
    )
}

/// Builds the current help screen.
#[must_use]
pub fn help_text() -> String {
    let mut help = String::new();
    writeln!(help, "bwu - Bitwarden/Vaultwarden CLI (M1 skeleton)")
        .expect("writing to String cannot fail");
    writeln!(help).expect("writing to String cannot fail");
    writeln!(help, "Usage: bwu <command> [options]").expect("writing to String cannot fail");
    writeln!(help).expect("writing to String cannot fail");
    writeln!(help, "Planned command groups:").expect("writing to String cannot fail");

    for group in BWU_COMMANDS {
        writeln!(
            help,
            "  {:<8} {:<64} [{}]",
            group.name,
            group.summary,
            group.operations.join(", ")
        )
        .expect("writing to String cannot fail");
    }

    writeln!(help).expect("writing to String cannot fail");
    writeln!(help, "{M1_BOUNDARY}.").expect("writing to String cannot fail");
    help
}
