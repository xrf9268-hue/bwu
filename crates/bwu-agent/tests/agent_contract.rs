use std::process::Command;

fn run_agent(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bwu-agent"))
        .args(args)
        .output()
        .expect("bwu-agent binary should run")
}

#[test]
fn agent_help_lists_planned_local_socket_commands() {
    let output = run_agent(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help output should be utf-8");
    for expected in [
        "start",
        "stop",
        "status",
        "socket",
        "timeout",
        "900 seconds",
    ] {
        assert!(
            stdout.contains(expected),
            "agent help output should mention {expected:?}:\n{stdout}"
        );
    }
}

#[test]
fn agent_start_fails_with_explicit_not_implemented_error() {
    let output = run_agent(&["start"]);

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("error output should be utf-8");
    assert!(
        stderr.contains("not implemented"),
        "agent operation should say it is not implemented:\n{stderr}"
    );
    assert!(
        stderr.contains("Unix socket agent"),
        "agent error should preserve the local-socket boundary:\n{stderr}"
    );
}
