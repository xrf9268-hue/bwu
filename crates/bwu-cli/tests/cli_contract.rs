use std::process::Command;

fn run_bwu(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bwu"))
        .args(args)
        .output()
        .expect("bwu binary should run")
}

#[test]
fn bwu_help_lists_planned_command_groups() {
    let output = run_bwu(&["--help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help output should be utf-8");
    for expected in [
        "account", "vault", "item", "otp", "passkey", "agent", "config",
    ] {
        assert!(
            stdout.contains(expected),
            "help output should mention {expected:?}:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("M1 skeleton"),
        "help should make the skeleton state explicit:\n{stdout}"
    );
}

#[test]
fn bwu_real_operations_fail_with_explicit_not_implemented_error() {
    let output = run_bwu(&["item", "list"]);

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("error output should be utf-8");
    assert!(
        stderr.contains("not implemented"),
        "real operation should say it is not implemented:\n{stderr}"
    );
    assert!(
        stderr.contains("no network, crypto, or vault cache implementation"),
        "error should document the M1 boundary:\n{stderr}"
    );
}
