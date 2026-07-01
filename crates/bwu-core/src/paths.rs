//! Config, cache, data, and runtime path primitives for the `bwu` namespace.

use std::{
    env, fmt, fs, io,
    path::{Path, PathBuf},
};

use crate::namespace::{
    AGENT_SOCKET_NAME, CACHE_DIR_NAME, CONFIG_DIR_NAME, DATA_DIR_NAME, RUNTIME_DIR_NAME,
};

/// Root directory override kind accepted by test-oriented command-line flags.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RootKind {
    /// Root for the config namespace directory.
    Config,
    /// Root for the cache namespace directory.
    Cache,
    /// Root for the data namespace directory.
    Data,
    /// Root for the runtime namespace directory.
    Runtime,
}

impl RootKind {
    /// Returns the command-line flag for this override kind.
    #[must_use]
    pub fn flag(self) -> &'static str {
        match self {
            Self::Config => "--config-root",
            Self::Cache => "--cache-root",
            Self::Data => "--data-root",
            Self::Runtime => "--runtime-root",
        }
    }

    fn from_flag(flag: &str) -> Option<Self> {
        match flag {
            "--config-root" => Some(Self::Config),
            "--cache-root" => Some(Self::Cache),
            "--data-root" => Some(Self::Data),
            "--runtime-root" => Some(Self::Runtime),
            _ => None,
        }
    }
}

/// Test-oriented root overrides for path resolution.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct RootOverrides {
    /// Override for the platform config root.
    pub config: Option<PathBuf>,
    /// Override for the platform cache root.
    pub cache: Option<PathBuf>,
    /// Override for the platform data root.
    pub data: Option<PathBuf>,
    /// Override for the platform runtime root.
    pub runtime: Option<PathBuf>,
}

impl RootOverrides {
    /// Sets one override path.
    pub fn set(&mut self, kind: RootKind, path: impl Into<PathBuf>) {
        let path = Some(path.into());
        match kind {
            RootKind::Config => self.config = path,
            RootKind::Cache => self.cache = path,
            RootKind::Data => self.data = path,
            RootKind::Runtime => self.runtime = path,
        }
    }
}

/// Fully resolved `bwu` local state paths.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AppPaths {
    /// Config directory under the `bwu` namespace.
    pub config_dir: PathBuf,
    /// Cache directory under the `bwu` namespace.
    pub cache_dir: PathBuf,
    /// Data directory under the `bwu` namespace.
    pub data_dir: PathBuf,
    /// Runtime directory under the `bwu` namespace.
    pub runtime_dir: PathBuf,
    /// Planned agent socket path under the runtime directory.
    pub agent_socket: PathBuf,
}

impl AppPaths {
    /// Resolves all local state paths without creating them.
    ///
    /// Explicit overrides take precedence and are namespaced by appending
    /// `bwu`; this keeps tests isolated without bypassing the namespace policy.
    pub fn resolve(overrides: &RootOverrides) -> Result<Self, PathError> {
        let runtime = RuntimePaths::resolve(overrides)?;

        Ok(Self {
            config_dir: config_root(overrides)?.join(CONFIG_DIR_NAME),
            cache_dir: cache_root(overrides)?.join(CACHE_DIR_NAME),
            data_dir: data_root(overrides)?.join(DATA_DIR_NAME),
            runtime_dir: runtime.runtime_dir,
            agent_socket: runtime.agent_socket,
        })
    }

    /// Creates the namespace directories with owner-only permissions where the
    /// platform supports POSIX-style modes.
    pub fn ensure_owner_only_dirs(&self) -> Result<(), PathError> {
        for dir in [
            &self.config_dir,
            &self.cache_dir,
            &self.data_dir,
            &self.runtime_dir,
        ] {
            ensure_owner_only_dir(dir)?;
        }
        Ok(())
    }
}

/// Resolved runtime-only paths for `bwu-agent`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimePaths {
    /// Runtime directory under the `bwu` namespace.
    pub runtime_dir: PathBuf,
    /// Planned agent socket path under the runtime directory.
    pub agent_socket: PathBuf,
}

impl RuntimePaths {
    /// Resolves runtime paths without requiring config, cache, data, or home.
    pub fn resolve(overrides: &RootOverrides) -> Result<Self, PathError> {
        let runtime_dir = runtime_root(overrides)?.join(RUNTIME_DIR_NAME);
        let agent_socket = runtime_dir.join(AGENT_SOCKET_NAME);
        Ok(Self {
            runtime_dir,
            agent_socket,
        })
    }

    /// Creates the runtime namespace directory with owner-only permissions where
    /// supported.
    pub fn ensure_owner_only_dir(&self) -> Result<(), PathError> {
        ensure_owner_only_dir(&self.runtime_dir)
    }
}

/// Path resolution or creation failure.
#[derive(Debug)]
pub enum PathError {
    /// A default path needs `$HOME`, but it is unavailable.
    MissingHome {
        /// Path category that needed `$HOME`.
        kind: &'static str,
    },
    /// Filesystem operation failed.
    Io {
        /// Path being created or permissioned.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHome { kind } => write!(
                formatter,
                "cannot resolve bwu {kind} directory without HOME or an explicit root override"
            ),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "cannot prepare bwu path {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingHome { .. } => None,
            Self::Io { source, .. } => Some(source),
        }
    }
}

/// Root override parsing failure.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RootOverrideParseError {
    /// A supported flag was passed without a following path.
    MissingValue {
        /// Flag that requires a value.
        flag: &'static str,
    },
    /// A flag is known but not accepted by the current binary.
    UnsupportedFlag {
        /// Unsupported flag.
        flag: &'static str,
    },
}

impl fmt::Display for RootOverrideParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue { flag } => write!(formatter, "{flag} requires a path value"),
            Self::UnsupportedFlag { flag } => write!(formatter, "{flag} is not supported here"),
        }
    }
}

impl std::error::Error for RootOverrideParseError {}

/// Extracts supported root overrides from an argument vector.
pub fn extract_root_overrides(
    args: impl IntoIterator<Item = String>,
    allowed: &[RootKind],
) -> Result<(Vec<String>, RootOverrides), RootOverrideParseError> {
    let mut sanitized = Vec::new();
    let mut overrides = RootOverrides::default();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if let Some(kind) = RootKind::from_flag(&arg) {
            if !allowed.contains(&kind) {
                return Err(RootOverrideParseError::UnsupportedFlag { flag: kind.flag() });
            }
            let value = args
                .next()
                .ok_or(RootOverrideParseError::MissingValue { flag: kind.flag() })?;
            overrides.set(kind, value);
        } else {
            sanitized.push(arg);
        }
    }

    Ok((sanitized, overrides))
}

/// Environment variables used by default path resolution.
#[must_use]
pub fn default_root_env_vars() -> &'static [&'static str] {
    &[
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
        "HOME",
    ]
}

fn config_root(overrides: &RootOverrides) -> Result<PathBuf, PathError> {
    override_or_env(
        overrides.config.as_ref(),
        "XDG_CONFIG_HOME",
        Some(".config"),
        "config",
    )
}

fn cache_root(overrides: &RootOverrides) -> Result<PathBuf, PathError> {
    override_or_env(
        overrides.cache.as_ref(),
        "XDG_CACHE_HOME",
        Some(".cache"),
        "cache",
    )
}

fn data_root(overrides: &RootOverrides) -> Result<PathBuf, PathError> {
    override_or_env(
        overrides.data.as_ref(),
        "XDG_DATA_HOME",
        Some(".local/share"),
        "data",
    )
}

fn runtime_root(overrides: &RootOverrides) -> Result<PathBuf, PathError> {
    if let Some(root) = &overrides.runtime {
        return Ok(root.clone());
    }
    if let Some(root) = env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(root));
    }
    let home = env::var_os("HOME").ok_or(PathError::MissingHome { kind: "runtime" })?;
    Ok(PathBuf::from(home).join(".local/run"))
}

fn override_or_env(
    override_root: Option<&PathBuf>,
    xdg_var: &'static str,
    home_child: Option<&'static str>,
    kind: &'static str,
) -> Result<PathBuf, PathError> {
    if let Some(root) = override_root {
        return Ok(root.clone());
    }
    if let Some(root) = env::var_os(xdg_var) {
        return Ok(PathBuf::from(root));
    }

    let Some(home_child) = home_child else {
        return Err(PathError::MissingHome { kind });
    };
    let home = env::var_os("HOME").ok_or(PathError::MissingHome { kind })?;
    Ok(PathBuf::from(home).join(home_child))
}

fn ensure_owner_only_dir(path: &Path) -> Result<(), PathError> {
    fs::create_dir_all(path).map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    set_owner_only_permissions(path)
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), PathError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<(), PathError> {
    Ok(())
}
