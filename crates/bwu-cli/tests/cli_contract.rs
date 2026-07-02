use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn run_bwu(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bwu"))
        .args(args)
        .output()
        .expect("bwu binary should run")
}

fn temp_tree(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("bwu-cli-{name}-{}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path).expect("stale test tree should be removable");
    }
    path
}

fn path_arg(path: &Path) -> String {
    path.to_str()
        .expect("temporary test path should be utf-8")
        .to_string()
}

fn run_bwu_without_home(args: &[String], rbw_root: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bwu"))
        .args(args)
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .env("RBW_CONFIG_HOME", rbw_root.join("config"))
        .env("RBW_CACHE_HOME", rbw_root.join("cache"))
        .env("RBW_RUNTIME_DIR", rbw_root.join("runtime"))
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

#[test]
fn bwu_not_implemented_errors_do_not_echo_secret_arguments() {
    let output = run_bwu(&[
        "account",
        "login",
        "--password",
        "test-master-password",
        "--client-secret",
        "test-api-secret",
    ]);

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("error output should be utf-8");
    assert!(
        stderr.contains("account login"),
        "error should keep a safe command identifier:\n{stderr}"
    );
    for leaked in ["test-master-password", "test-api-secret"] {
        assert!(
            !stderr.contains(leaked),
            "not-implemented error leaked secret argument {leaked:?}:\n{stderr}"
        );
    }
}

#[test]
fn cli_uses_temp_roots_and_does_not_read_user_home_state() {
    let temp = temp_tree("temp-roots");
    let rbw_root = temp.join("rbw");
    let args = vec![
        "item".to_string(),
        "list".to_string(),
        "--config-root".to_string(),
        path_arg(&temp.join("config-root")),
        "--cache-root".to_string(),
        path_arg(&temp.join("cache-root")),
        "--data-root".to_string(),
        path_arg(&temp.join("data-root")),
        "--runtime-root".to_string(),
        path_arg(&temp.join("runtime-root")),
    ];

    let output = run_bwu_without_home(&args, &rbw_root);

    assert_eq!(output.status.code(), Some(2));
    for expected in [
        temp.join("config-root").join("bwu"),
        temp.join("cache-root").join("bwu"),
        temp.join("data-root").join("bwu"),
        temp.join("runtime-root").join("bwu"),
    ] {
        assert!(
            expected.is_dir(),
            "command should create bwu temp root directory: {}",
            expected.display()
        );
    }
    assert!(
        !rbw_root.exists(),
        "command must not read or create rbw state even when rbw env vars are present"
    );

    fs::remove_dir_all(temp).expect("test temp tree should be removable");
}

#[test]
fn cli_paths_ignore_malformed_xdg_roots() {
    let temp = temp_tree("malformed-xdg-roots");
    let home = temp.join("home");
    let cwd = temp.join("cwd");
    fs::create_dir_all(&cwd).expect("test working directory should be creatable");

    let output = Command::new(env!("CARGO_BIN_EXE_bwu"))
        .args(["item", "list"])
        .current_dir(&cwd)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", "relative-config")
        .env("XDG_CACHE_HOME", "")
        .env("XDG_DATA_HOME", "relative-data")
        .env("XDG_RUNTIME_DIR", "relative-runtime")
        .output()
        .expect("bwu binary should run");

    assert_eq!(output.status.code(), Some(2));
    for expected in [
        home.join(".config/bwu"),
        home.join(".cache/bwu"),
        home.join(".local/share/bwu"),
        home.join(".local/run/bwu"),
    ] {
        assert!(
            expected.is_dir(),
            "malformed XDG roots should fall back to a HOME-derived bwu directory: {}",
            expected.display()
        );
    }
    for unexpected in [
        cwd.join("relative-config"),
        cwd.join("bwu"),
        cwd.join("relative-data"),
        cwd.join("relative-runtime"),
    ] {
        assert!(
            !unexpected.exists(),
            "malformed XDG roots must not create relative state: {}",
            unexpected.display()
        );
    }

    fs::remove_dir_all(temp).expect("test temp tree should be removable");
}

#[test]
fn cli_paths_reject_malformed_home_fallbacks() {
    for (case, home, unexpected_home_root) in [
        ("empty-home", "", ".config"),
        ("relative-home", "relative-home", "relative-home"),
    ] {
        let temp = temp_tree(case);
        let cwd = temp.join("cwd");
        fs::create_dir_all(&cwd).expect("test working directory should be creatable");

        let output = Command::new(env!("CARGO_BIN_EXE_bwu"))
            .args(["item", "list"])
            .current_dir(&cwd)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", "relative-config")
            .env("XDG_CACHE_HOME", "")
            .env("XDG_DATA_HOME", "relative-data")
            .env("XDG_RUNTIME_DIR", "relative-runtime")
            .output()
            .expect("bwu binary should run");

        assert_eq!(
            output.status.code(),
            Some(74),
            "malformed HOME should fail closed instead of creating relative state"
        );
        let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
        assert!(
            stderr.contains("without HOME or an explicit root override"),
            "path error should explain the missing usable HOME fallback:\n{stderr}"
        );
        for unexpected in [
            cwd.join(unexpected_home_root),
            cwd.join(".cache"),
            cwd.join(".local"),
            cwd.join("relative-config"),
            cwd.join("relative-data"),
            cwd.join("relative-runtime"),
        ] {
            assert!(
                !unexpected.exists(),
                "malformed HOME/XDG roots must not create relative state: {}",
                unexpected.display()
            );
        }

        fs::remove_dir_all(temp).expect("test temp tree should be removable");
    }
}

#[test]
fn cli_paths_reject_relative_root_overrides() {
    for (case, invalid_flag, invalid_value) in [
        ("relative-config-root", "--config-root", "relative-config"),
        ("relative-cache-root", "--cache-root", "relative-cache"),
        ("relative-data-root", "--data-root", "relative-data"),
        (
            "relative-runtime-root",
            "--runtime-root",
            "relative-runtime",
        ),
    ] {
        let temp = temp_tree(case);
        let cwd = temp.join("cwd");
        fs::create_dir_all(&cwd).expect("test working directory should be creatable");

        let mut args = vec![
            "item".to_string(),
            "list".to_string(),
            "--config-root".to_string(),
            path_arg(&temp.join("config-root")),
            "--cache-root".to_string(),
            path_arg(&temp.join("cache-root")),
            "--data-root".to_string(),
            path_arg(&temp.join("data-root")),
            "--runtime-root".to_string(),
            path_arg(&temp.join("runtime-root")),
        ];
        let invalid_index = args
            .iter()
            .position(|arg| arg == invalid_flag)
            .expect("test args should include invalid flag")
            + 1;
        args[invalid_index] = invalid_value.to_string();

        let output = Command::new(env!("CARGO_BIN_EXE_bwu"))
            .args(&args)
            .current_dir(&cwd)
            .env_remove("HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_CACHE_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .output()
            .expect("bwu binary should run");

        assert_eq!(
            output.status.code(),
            Some(64),
            "{invalid_flag} should reject relative root overrides"
        );
        let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
        assert!(
            stderr.contains("root override must be absolute"),
            "relative override error should explain the absolute-root requirement:\n{stderr}"
        );
        assert!(
            !cwd.join(invalid_value).exists(),
            "relative override must not create cwd-relative state for {invalid_flag}"
        );
        for root in ["config-root", "cache-root", "data-root", "runtime-root"] {
            assert!(
                !temp.join(root).join("bwu").exists(),
                "relative override rejection should happen before creating any bwu namespace directories"
            );
        }

        fs::remove_dir_all(temp).expect("test temp tree should be removable");
    }
}

#[test]
fn every_planned_command_accepts_temp_root_overrides() {
    let commands = [
        ("account", "status"),
        ("vault", "sync"),
        ("item", "list"),
        ("otp", "code"),
        ("passkey", "get"),
        ("agent", "status"),
        ("config", "show"),
    ];

    for (group, operation) in commands {
        let temp = temp_tree(&format!("{group}-{operation}"));
        let rbw_root = temp.join("rbw");
        let args = vec![
            group.to_string(),
            operation.to_string(),
            "--config-root".to_string(),
            path_arg(&temp.join("config-root")),
            "--cache-root".to_string(),
            path_arg(&temp.join("cache-root")),
            "--data-root".to_string(),
            path_arg(&temp.join("data-root")),
            "--runtime-root".to_string(),
            path_arg(&temp.join("runtime-root")),
        ];

        let output = run_bwu_without_home(&args, &rbw_root);

        assert_eq!(
            output.status.code(),
            Some(2),
            "{group} {operation} should accept temp root overrides"
        );
        let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
        assert!(
            stderr.contains("not implemented"),
            "{group} {operation} should reach the planned command path:\n{stderr}"
        );
        assert!(
            !rbw_root.exists(),
            "{group} {operation} must not create rbw state"
        );

        fs::remove_dir_all(temp).expect("test temp tree should be removable");
    }
}
