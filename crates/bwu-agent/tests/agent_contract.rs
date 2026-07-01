use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn run_agent(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bwu-agent"))
        .args(args)
        .output()
        .expect("bwu-agent binary should run")
}

fn temp_tree(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("bwu-agent-{name}-{}", std::process::id()));
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

#[test]
fn agent_commands_accept_temp_runtime_root_override() {
    for operation in ["start", "stop", "status"] {
        let temp = temp_tree(operation);
        let rbw_root = temp.join("rbw");
        let output = Command::new(env!("CARGO_BIN_EXE_bwu-agent"))
            .args([
                operation,
                "--runtime-root",
                path_arg(&temp.join("runtime-root")).as_str(),
            ])
            .env_remove("HOME")
            .env_remove("XDG_RUNTIME_DIR")
            .env("RBW_RUNTIME_DIR", rbw_root.join("runtime"))
            .output()
            .expect("bwu-agent binary should run");

        assert_eq!(output.status.code(), Some(2));
        assert!(
            temp.join("runtime-root").join("bwu").is_dir(),
            "agent command should create bwu runtime directory"
        );
        assert!(
            !rbw_root.exists(),
            "agent command must not create rbw runtime state"
        );

        fs::remove_dir_all(temp).expect("test temp tree should be removable");
    }
}

#[test]
fn agent_runtime_fallback_is_per_user_when_xdg_runtime_dir_is_unset() {
    let temp = temp_tree("runtime-fallback");
    let home = temp.join("home");
    let shared_tmp = temp.join("shared-tmp");
    let rbw_root = temp.join("rbw");

    let output = Command::new(env!("CARGO_BIN_EXE_bwu-agent"))
        .arg("status")
        .env("HOME", &home)
        .env("TMPDIR", &shared_tmp)
        .env_remove("XDG_RUNTIME_DIR")
        .env("RBW_RUNTIME_DIR", rbw_root.join("runtime"))
        .output()
        .expect("bwu-agent binary should run");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        home.join(".local/run/bwu").is_dir(),
        "agent should create a user-scoped runtime fallback"
    );
    assert!(
        !shared_tmp.join("bwu").exists(),
        "agent runtime fallback must not use a shared temp namespace"
    );
    assert!(
        !rbw_root.exists(),
        "agent command must not create rbw runtime state"
    );

    fs::remove_dir_all(temp).expect("test temp tree should be removable");
}

#[test]
fn agent_paths_ignore_malformed_xdg_runtime_dir() {
    for (case, invalid_runtime, unexpected_relative) in [
        ("empty-runtime", "", "bwu"),
        ("relative-runtime", "relative-runtime", "relative-runtime"),
    ] {
        let temp = temp_tree(case);
        let home = temp.join("home");
        let cwd = temp.join("cwd");
        let rbw_root = temp.join("rbw");
        fs::create_dir_all(&cwd).expect("test working directory should be creatable");

        let output = Command::new(env!("CARGO_BIN_EXE_bwu-agent"))
            .arg("status")
            .current_dir(&cwd)
            .env("HOME", &home)
            .env("XDG_RUNTIME_DIR", invalid_runtime)
            .env("RBW_RUNTIME_DIR", rbw_root.join("runtime"))
            .output()
            .expect("bwu-agent binary should run");

        assert_eq!(output.status.code(), Some(2));
        assert!(
            home.join(".local/run/bwu").is_dir(),
            "malformed XDG_RUNTIME_DIR should fall back to a HOME-derived bwu runtime directory"
        );
        assert!(
            !cwd.join(unexpected_relative).exists(),
            "malformed XDG_RUNTIME_DIR must not create relative runtime state"
        );
        assert!(
            !rbw_root.exists(),
            "agent command must not create rbw runtime state"
        );

        fs::remove_dir_all(temp).expect("test temp tree should be removable");
    }
}

#[test]
fn agent_paths_reject_malformed_home_runtime_fallbacks() {
    for (case, home, unexpected_home_root) in [
        ("empty-home", "", ".local"),
        ("relative-home", "relative-home", "relative-home"),
    ] {
        let temp = temp_tree(case);
        let cwd = temp.join("cwd");
        let rbw_root = temp.join("rbw");
        fs::create_dir_all(&cwd).expect("test working directory should be creatable");

        let output = Command::new(env!("CARGO_BIN_EXE_bwu-agent"))
            .arg("status")
            .current_dir(&cwd)
            .env("HOME", home)
            .env_remove("XDG_RUNTIME_DIR")
            .env("RBW_RUNTIME_DIR", rbw_root.join("runtime"))
            .output()
            .expect("bwu-agent binary should run");

        assert_eq!(
            output.status.code(),
            Some(74),
            "malformed HOME should fail closed instead of creating relative runtime state"
        );
        let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
        assert!(
            stderr.contains("without HOME or an explicit root override"),
            "path error should explain the missing usable HOME fallback:\n{stderr}"
        );
        for unexpected in [
            cwd.join(unexpected_home_root),
            cwd.join(".local"),
            cwd.join("bwu"),
        ] {
            assert!(
                !unexpected.exists(),
                "malformed HOME must not create relative runtime state: {}",
                unexpected.display()
            );
        }
        assert!(
            !rbw_root.exists(),
            "agent command must not create rbw runtime state"
        );

        fs::remove_dir_all(temp).expect("test temp tree should be removable");
    }
}

#[test]
fn agent_paths_reject_relative_runtime_root_override() {
    let temp = temp_tree("relative-runtime-root");
    let cwd = temp.join("cwd");
    let rbw_root = temp.join("rbw");
    fs::create_dir_all(&cwd).expect("test working directory should be creatable");

    let output = Command::new(env!("CARGO_BIN_EXE_bwu-agent"))
        .args(["status", "--runtime-root", "relative-runtime"])
        .current_dir(&cwd)
        .env_remove("HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .env("RBW_RUNTIME_DIR", rbw_root.join("runtime"))
        .output()
        .expect("bwu-agent binary should run");

    assert_eq!(
        output.status.code(),
        Some(74),
        "relative runtime override should fail closed"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf-8");
    assert!(
        stderr.contains("root override must be absolute"),
        "relative override error should explain the absolute-root requirement:\n{stderr}"
    );
    assert!(
        !cwd.join("relative-runtime").exists(),
        "relative runtime override must not create cwd-relative state"
    );
    assert!(
        !rbw_root.exists(),
        "agent command must not create rbw runtime state"
    );

    fs::remove_dir_all(temp).expect("test temp tree should be removable");
}
