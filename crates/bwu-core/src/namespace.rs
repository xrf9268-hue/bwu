//! Shared namespace constants for future config, cache, and runtime paths.

/// Fresh namespace for all `bwu` config, cache, and runtime state.
pub const APP_NAMESPACE: &str = "bwu";

/// Config directory name under the platform-specific user config root.
pub const CONFIG_DIR_NAME: &str = "bwu";

/// Cache directory name under the platform-specific user cache root.
pub const CACHE_DIR_NAME: &str = "bwu";

/// Data directory name under the platform-specific user data root.
pub const DATA_DIR_NAME: &str = "bwu";

/// Runtime directory name for local sockets and process state.
pub const RUNTIME_DIR_NAME: &str = "bwu";

/// Planned Unix socket filename for the optional local agent.
pub const AGENT_SOCKET_NAME: &str = "bwu-agent.sock";

/// Default unlocked-key lifetime for the optional local agent.
pub const AGENT_DEFAULT_TIMEOUT_SECONDS: u64 = 900;
