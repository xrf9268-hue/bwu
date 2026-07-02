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
    /// A default path needs an absolute `$HOME`, but it is unavailable.
    MissingHome {
        /// Path category that needed an absolute `$HOME`.
        kind: &'static str,
    },
    /// An explicit command root override was not absolute.
    RelativeRootOverride {
        /// Path category whose override was relative.
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
            Self::RelativeRootOverride { kind } => write!(
                formatter,
                "cannot resolve bwu {kind} directory from a relative root override; root override must be absolute"
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
            Self::MissingHome { .. } | Self::RelativeRootOverride { .. } => None,
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
    /// A supported root override flag was given a relative path.
    RelativeValue {
        /// Flag that received a relative path.
        flag: &'static str,
    },
}

impl fmt::Display for RootOverrideParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue { flag } => write!(formatter, "{flag} requires a path value"),
            Self::UnsupportedFlag { flag } => write!(formatter, "{flag} is not supported here"),
            Self::RelativeValue { flag } => {
                write!(formatter, "{flag} root override must be absolute")
            }
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
            let value = PathBuf::from(value);
            if !value.is_absolute() {
                return Err(RootOverrideParseError::RelativeValue { flag: kind.flag() });
            }
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
    if let Some(root) = absolute_override_root(overrides.runtime.as_ref(), "runtime")? {
        return Ok(root);
    }
    if let Some(root) = absolute_env_root("XDG_RUNTIME_DIR") {
        return Ok(root);
    }
    Ok(home_root("runtime")?.join(".local/run"))
}

fn override_or_env(
    override_root: Option<&PathBuf>,
    xdg_var: &'static str,
    home_child: Option<&'static str>,
    kind: &'static str,
) -> Result<PathBuf, PathError> {
    if let Some(root) = absolute_override_root(override_root, kind)? {
        return Ok(root);
    }
    if let Some(root) = absolute_env_root(xdg_var) {
        return Ok(root);
    }

    let Some(home_child) = home_child else {
        return Err(PathError::MissingHome { kind });
    };
    Ok(home_root(kind)?.join(home_child))
}

fn absolute_override_root(
    override_root: Option<&PathBuf>,
    kind: &'static str,
) -> Result<Option<PathBuf>, PathError> {
    let Some(root) = override_root else {
        return Ok(None);
    };
    if root.is_absolute() {
        return Ok(Some(root.clone()));
    }
    Err(PathError::RelativeRootOverride { kind })
}

fn absolute_env_root(name: &'static str) -> Option<PathBuf> {
    let root = PathBuf::from(env::var_os(name)?);
    root.is_absolute().then_some(root)
}

fn home_root(kind: &'static str) -> Result<PathBuf, PathError> {
    let root = PathBuf::from(env::var_os("HOME").ok_or(PathError::MissingHome { kind })?);
    root.is_absolute()
        .then_some(root)
        .ok_or(PathError::MissingHome { kind })
}

#[cfg(unix)]
const OWNER_ONLY_DIR_MODE: u32 = 0o700;

#[cfg(unix)]
trait DirOps {
    fn path_is_dir(&self, path: &Path) -> bool;
    fn create_dir_all_with_mode(&self, path: &Path, mode: u32) -> io::Result<()>;
    fn owner_id(&self, path: &Path) -> io::Result<u32>;
    fn effective_owner_id(&self) -> io::Result<u32>;
    fn permissions_mode(&self, path: &Path) -> io::Result<u32>;
    fn set_permissions_mode(&self, path: &Path, mode: u32) -> io::Result<()>;
}

#[cfg(unix)]
struct RealDirOps;

#[cfg(unix)]
impl DirOps for RealDirOps {
    fn path_is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn create_dir_all_with_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(mode).create(path)
    }

    fn owner_id(&self, path: &Path) -> io::Result<u32> {
        use std::os::unix::fs::MetadataExt;

        Ok(fs::metadata(path)?.uid())
    }

    fn effective_owner_id(&self) -> io::Result<u32> {
        Ok(rustix::process::geteuid().as_raw())
    }

    fn permissions_mode(&self, path: &Path) -> io::Result<u32> {
        use std::os::unix::fs::PermissionsExt;

        Ok(fs::metadata(path)?.permissions().mode() & 0o777)
    }

    fn set_permissions_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }
}

#[cfg(unix)]
fn ensure_owner_only_dir(path: &Path) -> Result<(), PathError> {
    let ops = RealDirOps;
    ensure_owner_only_dir_with_ops(path, &ops)
}

#[cfg(unix)]
fn ensure_owner_only_dir_with_ops(path: &Path, ops: &impl DirOps) -> Result<(), PathError> {
    let existed = ops.path_is_dir(path);
    ops.create_dir_all_with_mode(path, OWNER_ONLY_DIR_MODE)
        .map_err(|source| PathError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    let mode = ops.permissions_mode(path).map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let owner_id = ops.owner_id(path).map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let effective_owner_id = ops.effective_owner_id().map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if owner_id != effective_owner_id {
        return Err(PathError::Io {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "bwu directory owner uid {owner_id} does not match current effective uid {effective_owner_id}"
                ),
            ),
        });
    }

    if mode == OWNER_ONLY_DIR_MODE {
        return Ok(());
    }

    ops.set_permissions_mode(path, OWNER_ONLY_DIR_MODE)
        .map_err(|source| PathError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    let mode = ops.permissions_mode(path).map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if mode == OWNER_ONLY_DIR_MODE {
        return Ok(());
    }

    let creation_context = if existed { "existing" } else { "newly created" };
    Err(PathError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{creation_context} bwu directory is not owner-only after chmod: mode {mode:o}"
            ),
        ),
    })
}

#[cfg(not(unix))]
fn ensure_owner_only_dir(path: &Path) -> Result<(), PathError> {
    fs::create_dir_all(path).map_err(|source| PathError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        io,
    };

    struct FakeDirOps {
        existed: bool,
        mode: Cell<u32>,
        owner_id: Cell<u32>,
        effective_owner_id: Cell<u32>,
        create_modes: RefCell<Vec<u32>>,
        chmod_calls: Cell<usize>,
        chmod_error: bool,
    }

    impl FakeDirOps {
        fn missing_created_with_mode(mode: u32) -> Self {
            Self {
                existed: false,
                mode: Cell::new(mode),
                owner_id: Cell::new(1000),
                effective_owner_id: Cell::new(1000),
                create_modes: RefCell::new(Vec::new()),
                chmod_calls: Cell::new(0),
                chmod_error: false,
            }
        }

        fn existing_with_mode(mode: u32) -> Self {
            Self {
                existed: true,
                mode: Cell::new(mode),
                owner_id: Cell::new(1000),
                effective_owner_id: Cell::new(1000),
                create_modes: RefCell::new(Vec::new()),
                chmod_calls: Cell::new(0),
                chmod_error: false,
            }
        }

        fn with_chmod_error(mut self) -> Self {
            self.chmod_error = true;
            self
        }

        fn with_owner_id(self, owner_id: u32) -> Self {
            self.owner_id.set(owner_id);
            self
        }

        fn with_effective_owner_id(self, effective_owner_id: u32) -> Self {
            self.effective_owner_id.set(effective_owner_id);
            self
        }
    }

    impl DirOps for FakeDirOps {
        fn path_is_dir(&self, _path: &Path) -> bool {
            self.existed
        }

        fn create_dir_all_with_mode(&self, _path: &Path, mode: u32) -> io::Result<()> {
            self.create_modes.borrow_mut().push(mode);
            Ok(())
        }

        fn owner_id(&self, _path: &Path) -> io::Result<u32> {
            Ok(self.owner_id.get())
        }

        fn effective_owner_id(&self) -> io::Result<u32> {
            Ok(self.effective_owner_id.get())
        }

        fn permissions_mode(&self, _path: &Path) -> io::Result<u32> {
            Ok(self.mode.get())
        }

        fn set_permissions_mode(&self, _path: &Path, mode: u32) -> io::Result<()> {
            self.chmod_calls.set(self.chmod_calls.get() + 1);
            if self.chmod_error {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "synthetic chmod failure",
                ));
            }
            self.mode.set(mode);
            Ok(())
        }
    }

    #[test]
    fn newly_created_unix_dirs_are_created_owner_only_without_post_creation_chmod() {
        let ops = FakeDirOps::missing_created_with_mode(0o700);

        ensure_owner_only_dir_with_ops(Path::new("/synthetic/bwu"), &ops)
            .expect("new directory should be private at creation time");

        assert_eq!(ops.create_modes.borrow().as_slice(), &[0o700]);
        assert_eq!(
            ops.chmod_calls.get(),
            0,
            "new private directories must not rely on a later chmod"
        );
    }

    #[test]
    fn existing_unix_dirs_fail_closed_when_owner_only_chmod_fails() {
        let ops = FakeDirOps::existing_with_mode(0o755).with_chmod_error();

        let err = ensure_owner_only_dir_with_ops(Path::new("/synthetic/bwu"), &ops)
            .expect_err("existing broad directory should fail if chmod fails");

        assert!(matches!(err, PathError::Io { .. }));
        assert_eq!(
            ops.chmod_calls.get(),
            1,
            "existing broad directories should be narrowed exactly once"
        );
    }

    #[test]
    fn existing_unix_dirs_fail_closed_when_owner_differs_from_effective_user() {
        let ops = FakeDirOps::existing_with_mode(0o700)
            .with_owner_id(2000)
            .with_effective_owner_id(1000);

        let err = ensure_owner_only_dir_with_ops(Path::new("/synthetic/bwu"), &ops)
            .expect_err("existing private directory owned by another uid should fail");

        assert!(matches!(err, PathError::Io { .. }));
        assert_eq!(
            ops.chmod_calls.get(),
            0,
            "mode changes cannot fix a directory owned by another user"
        );
    }
}
