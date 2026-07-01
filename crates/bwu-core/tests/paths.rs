use std::path::{Component, Path, PathBuf};

use bwu_core::{
    namespace::{AGENT_SOCKET_NAME, APP_NAMESPACE},
    paths::{AppPaths, RootOverrides, RuntimePaths, default_root_env_vars},
};

fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str().map(ToOwned::to_owned),
            _ => None,
        })
        .collect()
}

#[test]
fn paths_are_isolated_from_rbw_paths_and_environment_names() {
    let temp = std::env::temp_dir().join(format!(
        "bwu-paths-isolated-{}-{}",
        std::process::id(),
        line!()
    ));
    let overrides = RootOverrides {
        config: Some(temp.join("config-root")),
        cache: Some(temp.join("cache-root")),
        data: Some(temp.join("data-root")),
        runtime: Some(temp.join("runtime-root")),
    };

    let paths = AppPaths::resolve(&overrides).expect("path overrides should resolve");

    assert_eq!(APP_NAMESPACE, "bwu");
    assert_eq!(AGENT_SOCKET_NAME, "bwu-agent.sock");

    for resolved in [
        &paths.config_dir,
        &paths.cache_dir,
        &paths.data_dir,
        &paths.runtime_dir,
        &paths.agent_socket,
    ] {
        let components = path_components(resolved);
        assert!(
            components.iter().any(|component| component == "bwu"),
            "resolved path should include the bwu namespace: {}",
            resolved.display()
        );
        assert!(
            components.iter().all(|component| component != "rbw"),
            "resolved path must not use rbw namespace components: {}",
            resolved.display()
        );
    }

    assert!(
        !default_root_env_vars()
            .iter()
            .any(|name| name.to_ascii_lowercase().contains("rbw")),
        "default path resolution must not consult rbw environment variables"
    );
}

#[test]
fn paths_creation_uses_owner_only_permissions_where_supported() {
    let temp = std::env::temp_dir().join(format!(
        "bwu-paths-owner-only-{}-{}",
        std::process::id(),
        line!()
    ));
    let overrides = RootOverrides {
        config: Some(temp.join("config")),
        cache: Some(temp.join("cache")),
        data: Some(temp.join("data")),
        runtime: Some(temp.join("runtime")),
    };
    let paths = AppPaths::resolve(&overrides).expect("path overrides should resolve");

    paths
        .ensure_owner_only_dirs()
        .expect("path directories should be created");

    for dir in [
        &paths.config_dir,
        &paths.cache_dir,
        &paths.data_dir,
        &paths.runtime_dir,
    ] {
        assert!(
            dir.is_dir(),
            "expected directory to exist: {}",
            dir.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        for dir in [
            &paths.config_dir,
            &paths.cache_dir,
            &paths.data_dir,
            &paths.runtime_dir,
        ] {
            let mode = std::fs::metadata(dir)
                .unwrap_or_else(|err| panic!("metadata should load for {}: {err}", dir.display()))
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                mode,
                0o700,
                "directory should be owner-only: {}",
                dir.display()
            );
        }
    }

    std::fs::remove_dir_all(temp).expect("test temp tree should be removable");
}

#[test]
fn paths_reject_relative_root_overrides_before_namespace_creation() {
    let absolute = std::env::temp_dir().join(format!(
        "bwu-paths-relative-overrides-{}-{}",
        std::process::id(),
        line!()
    ));

    for (kind, overrides) in [
        (
            "config",
            RootOverrides {
                config: Some(PathBuf::from("relative-config")),
                cache: Some(absolute.join("cache")),
                data: Some(absolute.join("data")),
                runtime: Some(absolute.join("runtime")),
            },
        ),
        (
            "cache",
            RootOverrides {
                config: Some(absolute.join("config")),
                cache: Some(PathBuf::from("relative-cache")),
                data: Some(absolute.join("data")),
                runtime: Some(absolute.join("runtime")),
            },
        ),
        (
            "data",
            RootOverrides {
                config: Some(absolute.join("config")),
                cache: Some(absolute.join("cache")),
                data: Some(PathBuf::from("relative-data")),
                runtime: Some(absolute.join("runtime")),
            },
        ),
    ] {
        let err =
            AppPaths::resolve(&overrides).expect_err("relative root override should fail closed");
        let message = err.to_string();
        assert!(
            message.contains(kind),
            "error should name the invalid root kind {kind:?}: {message}"
        );
        assert!(
            message.contains("root override must be absolute"),
            "error should explain that overrides must be absolute: {message}"
        );
    }

    let err = RuntimePaths::resolve(&RootOverrides {
        config: None,
        cache: None,
        data: None,
        runtime: Some(PathBuf::from("relative-runtime")),
    })
    .expect_err("relative runtime override should fail closed");
    let message = err.to_string();
    assert!(
        message.contains("runtime"),
        "error should name the invalid runtime root: {message}"
    );
    assert!(
        message.contains("root override must be absolute"),
        "error should explain that overrides must be absolute: {message}"
    );

    assert!(
        !absolute.exists(),
        "relative override rejection must happen before creating any namespace directories"
    );
}
