//! Planned command metadata for M1 help output.

/// A planned command group exposed by a binary help screen.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CommandGroup {
    /// Top-level command group name.
    pub name: &'static str,
    /// Short user-facing summary.
    pub summary: &'static str,
    /// Planned subcommands in this group.
    pub operations: &'static [&'static str],
}

/// Planned command groups for the `bwu` binary.
pub const BWU_COMMANDS: &[CommandGroup] = &[
    CommandGroup {
        name: "account",
        summary: "login, logout, status, and endpoint selection",
        operations: &["login", "logout", "status"],
    },
    CommandGroup {
        name: "vault",
        summary: "sync, unlock, lock, and purge the encrypted local cache",
        operations: &["sync", "unlock", "lock", "purge"],
    },
    CommandGroup {
        name: "item",
        summary: "list, get, search, add, edit, and delete vault items",
        operations: &["list", "get", "search", "add", "edit", "delete"],
    },
    CommandGroup {
        name: "otp",
        summary: "generate TOTP codes from selected vault items",
        operations: &["code"],
    },
    CommandGroup {
        name: "passkey",
        summary: "list, get, export, and sign with stored passkeys",
        operations: &["list", "get", "export", "sign"],
    },
    CommandGroup {
        name: "agent",
        summary: "interact with the optional local Unix socket agent",
        operations: &["start", "stop", "status"],
    },
    CommandGroup {
        name: "config",
        summary: "show and set bwu namespace configuration",
        operations: &["show", "set-endpoint"],
    },
];

/// Planned command groups for the `bwu-agent` binary.
pub const AGENT_COMMANDS: &[CommandGroup] = &[CommandGroup {
    name: "agent",
    summary: "manage the optional local Unix socket process",
    operations: &["start", "stop", "status"],
}];

/// Returns true when an argument vector requests help or is empty.
#[must_use]
pub fn wants_help(args: &[String]) -> bool {
    args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h")
}

/// Returns true when the first argument is a planned `bwu` command group.
#[must_use]
pub fn is_planned_bwu_group(args: &[String]) -> bool {
    args.first().is_some_and(|candidate| {
        BWU_COMMANDS
            .iter()
            .any(|group| group.name == candidate.as_str())
    })
}

/// Builds a safe planned `bwu` operation label without echoing raw arguments.
#[must_use]
pub fn planned_bwu_operation_label(args: &[String]) -> Option<String> {
    let group_name = args.first()?.as_str();
    let group = BWU_COMMANDS.iter().find(|group| group.name == group_name)?;

    let mut label = group.name.to_string();
    if let Some(operation) = args
        .get(1)
        .and_then(|candidate| {
            group
                .operations
                .iter()
                .find(|operation| **operation == candidate.as_str())
        })
        .copied()
    {
        label.push(' ');
        label.push_str(operation);
    }

    Some(label)
}

/// Returns true when the first argument is a planned agent operation.
#[must_use]
pub fn is_planned_agent_operation(args: &[String]) -> bool {
    args.first().is_some_and(|candidate| {
        AGENT_COMMANDS[0]
            .operations
            .iter()
            .any(|operation| operation == &candidate.as_str())
    })
}

/// Builds a safe planned `bwu-agent` operation label without echoing raw arguments.
#[must_use]
pub fn planned_agent_operation_label(args: &[String]) -> Option<&'static str> {
    args.first().and_then(|candidate| {
        AGENT_COMMANDS[0]
            .operations
            .iter()
            .find(|operation| **operation == candidate.as_str())
            .copied()
    })
}
