//! Configuration Loading System
//!
//! Provides configuration loading from multiple sources with priority:
//! 1. Default values
//! 2. Environment variables
//! 3. Configuration files (highest priority)

use crate::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Configuration source type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Load from a file
    File(PathBuf),
    /// Load from environment variables
    Env,
    /// Use default values
    Default,
    /// Load from in-memory string (for testing)
    Memory(String),
}

/// Configuration value types
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    /// String value
    String(String),
    /// Integer value
    Integer(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Boolean(bool),
    /// Array of values
    Array(Vec<Self>),
    /// Table of key-value pairs
    Table(HashMap<String, Self>),
}

impl ConfigValue {
    /// Convert to string
    #[must_use]
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Convert to integer
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Convert to float
    #[must_use]
    pub const fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Convert to boolean
    #[must_use]
    pub const fn as_boolean(&self) -> Option<bool> {
        match self {
            Self::Boolean(b) => Some(*b),
            _ => None,
        }
    }
}

/// Log level configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogLevel {
    /// Trace level
    Trace,
    /// Debug level
    Debug,
    /// Info level
    #[default]
    Info,
    /// Warn level
    Warn,
    /// Error level
    Error,
}

impl std::str::FromStr for LogLevel {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(ConfigError::InvalidValue {
                field: "log_level".to_string(),
                message: format!("Invalid log level: {s}"),
            }),
        }
    }
}

/// Log format configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogFormat {
    /// JSON format
    #[default]
    Json,
    /// Pretty format
    Pretty,
    /// Compact format
    Compact,
}

impl std::str::FromStr for LogFormat {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "pretty" => Ok(Self::Pretty),
            "compact" => Ok(Self::Compact),
            _ => Err(ConfigError::InvalidValue {
                field: "log_format".to_string(),
                message: format!("Invalid log format: {s}"),
            }),
        }
    }
}

/// Log output configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum LogOutput {
    /// Output to stdout
    #[default]
    Stdout,
    /// Output to stderr
    Stderr,
    /// Output to file
    File,
    /// Output to both stdout and file
    Both,
}

impl std::str::FromStr for LogOutput {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            "file" => Ok(Self::File),
            "both" => Ok(Self::Both),
            _ => Err(ConfigError::InvalidValue {
                field: "log_output".to_string(),
                message: format!("Invalid log output: {s}"),
            }),
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Bind address
    pub bind_address: String,
    /// HTTP port
    pub port: u16,
    /// QUIC port
    pub quic_port: u16,
    /// Maximum number of connections
    pub max_connections: usize,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 9000,
            quic_port: 9001,
            max_connections: 1000,
            connection_timeout_ms: 30000,
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Data directory
    pub data_dir: PathBuf,
    /// Cache directory
    pub cache_dir: PathBuf,
    /// Maximum cache size in bytes
    pub max_cache_size_bytes: u64,
    /// Chunk size in bytes
    pub chunk_size: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Self {
            data_dir: home.join(".warp/data"),
            cache_dir: home.join(".warp/cache"),
            max_cache_size_bytes: 10 * 1024 * 1024 * 1024, // 10GB
            chunk_size: 1024 * 1024,                       // 1MB
        }
    }
}

/// Scheduler configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SchedulerConfig {
    /// Tick interval in milliseconds
    pub tick_interval_ms: u64,
    /// Maximum concurrent transfers
    pub max_concurrent_transfers: usize,
    /// Failover timeout in milliseconds
    pub failover_timeout_ms: u64,
    /// Use GPU acceleration
    pub use_gpu: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            tick_interval_ms: 50,
            max_concurrent_transfers: 100,
            failover_timeout_ms: 5000,
            use_gpu: true,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Log level
    pub level: LogLevel,
    /// Log format
    pub format: LogFormat,
    /// Log output
    pub output: LogOutput,
    /// File path for file output
    pub file_path: Option<PathBuf>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Json,
            output: LogOutput::Stdout,
            file_path: None,
        }
    }
}

/// Top-level warp configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct WarpConfig {
    /// Network configuration
    pub network: NetworkConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Scheduler configuration
    pub scheduler: SchedulerConfig,
    /// Logging configuration
    pub log: LogConfig,
}

/// Configuration loader
pub struct ConfigLoader {
    sources: Vec<ConfigSource>,
    env_prefix: Option<String>,
}

impl ConfigLoader {
    /// Create a new configuration loader
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: vec![ConfigSource::Default],
            env_prefix: None,
        }
    }

    /// Add a file source
    pub fn with_file(mut self, path: impl AsRef<Path>) -> Self {
        self.sources
            .push(ConfigSource::File(path.as_ref().to_path_buf()));
        self
    }

    /// Add environment variable source with prefix
    #[must_use]
    pub fn with_env_prefix(mut self, prefix: &str) -> Self {
        self.env_prefix = Some(prefix.to_string());
        self.sources.push(ConfigSource::Env);
        self
    }

    /// Load configuration from all sources
    pub fn load(&self) -> Result<WarpConfig> {
        let mut config = WarpConfig::default();

        for source in &self.sources {
            match source {
                ConfigSource::Default => {
                    // Already loaded via default
                }
                ConfigSource::File(path) => {
                    let content = std::fs::read_to_string(path)?;
                    let file_config: WarpConfig =
                        toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;
                    config = Self::merge_configs(config, file_config);
                }
                ConfigSource::Env => {
                    if let Some(prefix) = &self.env_prefix {
                        config = Self::apply_env_overrides(config, prefix)?;
                    }
                }
                ConfigSource::Memory(content) => {
                    let mem_config: WarpConfig =
                        toml::from_str(content).map_err(|e| ConfigError::Parse(e.to_string()))?;
                    config = Self::merge_configs(config, mem_config);
                }
            }
        }

        // Expand paths
        config.storage.data_dir = Self::expand_path(&config.storage.data_dir);
        config.storage.cache_dir = Self::expand_path(&config.storage.cache_dir);
        if let Some(ref path) = config.log.file_path {
            config.log.file_path = Some(Self::expand_path(path));
        }

        Ok(config)
    }

    /// Load configuration from a TOML string
    pub fn load_from_str(toml: &str) -> Result<WarpConfig> {
        let mut config: WarpConfig =
            toml::from_str(toml).map_err(|e| ConfigError::Parse(e.to_string()))?;

        // Expand paths
        config.storage.data_dir = Self::expand_path(&config.storage.data_dir);
        config.storage.cache_dir = Self::expand_path(&config.storage.cache_dir);
        if let Some(ref path) = config.log.file_path {
            config.log.file_path = Some(Self::expand_path(path));
        }

        Ok(config)
    }

    /// Get default configuration
    #[must_use]
    pub fn default_config() -> WarpConfig {
        WarpConfig::default()
    }

    /// Merge two configurations (new takes precedence)
    fn merge_configs(_base: WarpConfig, new: WarpConfig) -> WarpConfig {
        new
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(mut config: WarpConfig, prefix: &str) -> Result<WarpConfig> {
        // Network overrides
        if let Ok(val) = std::env::var(format!("{prefix}_NETWORK_BIND_ADDRESS")) {
            config.network.bind_address = val;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_NETWORK_PORT")) {
            config.network.port = val
                .parse()
                .map_err(|_| ConfigError::EnvVar(format!("Invalid port value: {val}")))?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_NETWORK_QUIC_PORT")) {
            config.network.quic_port = val
                .parse()
                .map_err(|_| ConfigError::EnvVar(format!("Invalid quic_port value: {val}")))?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_NETWORK_MAX_CONNECTIONS")) {
            config.network.max_connections = val.parse().map_err(|_| {
                ConfigError::EnvVar(format!("Invalid max_connections value: {val}"))
            })?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_NETWORK_CONNECTION_TIMEOUT_MS")) {
            config.network.connection_timeout_ms = val.parse().map_err(|_| {
                ConfigError::EnvVar(format!("Invalid connection_timeout_ms value: {val}"))
            })?;
        }

        // Storage overrides
        if let Ok(val) = std::env::var(format!("{prefix}_STORAGE_DATA_DIR")) {
            config.storage.data_dir = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var(format!("{prefix}_STORAGE_CACHE_DIR")) {
            config.storage.cache_dir = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var(format!("{prefix}_STORAGE_MAX_CACHE_SIZE_BYTES")) {
            config.storage.max_cache_size_bytes = val.parse().map_err(|_| {
                ConfigError::EnvVar(format!("Invalid max_cache_size_bytes value: {val}"))
            })?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_STORAGE_CHUNK_SIZE")) {
            config.storage.chunk_size = val
                .parse()
                .map_err(|_| ConfigError::EnvVar(format!("Invalid chunk_size value: {val}")))?;
        }

        // Scheduler overrides
        if let Ok(val) = std::env::var(format!("{prefix}_SCHEDULER_TICK_INTERVAL_MS")) {
            config.scheduler.tick_interval_ms = val.parse().map_err(|_| {
                ConfigError::EnvVar(format!("Invalid tick_interval_ms value: {val}"))
            })?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_SCHEDULER_MAX_CONCURRENT_TRANSFERS")) {
            config.scheduler.max_concurrent_transfers = val.parse().map_err(|_| {
                ConfigError::EnvVar(format!("Invalid max_concurrent_transfers value: {val}"))
            })?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_SCHEDULER_FAILOVER_TIMEOUT_MS")) {
            config.scheduler.failover_timeout_ms = val.parse().map_err(|_| {
                ConfigError::EnvVar(format!("Invalid failover_timeout_ms value: {val}"))
            })?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_SCHEDULER_USE_GPU")) {
            config.scheduler.use_gpu = val
                .parse()
                .map_err(|_| ConfigError::EnvVar(format!("Invalid use_gpu value: {val}")))?;
        }

        // Log overrides
        if let Ok(val) = std::env::var(format!("{prefix}_LOG_LEVEL")) {
            config.log.level = val.parse()?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_LOG_FORMAT")) {
            config.log.format = val.parse()?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_LOG_OUTPUT")) {
            config.log.output = val.parse()?;
        }
        if let Ok(val) = std::env::var(format!("{prefix}_LOG_FILE_PATH")) {
            config.log.file_path = Some(PathBuf::from(val));
        }

        Ok(config)
    }

    /// Expand path with tilde
    fn expand_path(path: &Path) -> PathBuf {
        if let Some(path_str) = path.to_str() {
            if path_str.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(&path_str[2..]);
                }
            }
        }
        path.to_path_buf()
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // SAFETY NOTE: This module uses unsafe std::env::set_var/remove_var calls.
    // These are unsafe in Rust 2024 because they can cause data races if called
    // concurrently. We mitigate this by:
    // 1. Using unique env var prefixes per test (NETPORT_, STORDIR_, etc.)
    // 2. Each test sets and removes its own env vars, avoiding cross-test interference
    // 3. Tests are run with `cargo test -- --test-threads=1` when debugging env issues
    // The env var manipulation is used to test config override behavior.

    #[test]
    fn test_config_source_variants() {
        let file_src = ConfigSource::File(PathBuf::from("/etc/config.toml"));
        assert!(matches!(file_src, ConfigSource::File(_)));

        let env_src = ConfigSource::Env;
        assert_eq!(env_src, ConfigSource::Env);

        let default_src = ConfigSource::Default;
        assert_eq!(default_src, ConfigSource::Default);

        let mem_src = ConfigSource::Memory("config data".to_string());
        assert!(matches!(mem_src, ConfigSource::Memory(_)));
    }

    #[test]
    fn test_config_value_types() {
        let str_val = ConfigValue::String("test".to_string());
        assert_eq!(str_val.as_string(), Some("test"));
        assert_eq!(str_val.as_integer(), None);

        let int_val = ConfigValue::Integer(42);
        assert_eq!(int_val.as_integer(), Some(42));
        assert_eq!(int_val.as_string(), None);

        let float_val = ConfigValue::Float(3.14);
        assert_eq!(float_val.as_float(), Some(3.14));
        assert_eq!(float_val.as_integer(), None);

        let bool_val = ConfigValue::Boolean(true);
        assert_eq!(bool_val.as_boolean(), Some(true));
        assert_eq!(bool_val.as_string(), None);

        let arr_val = ConfigValue::Array(vec![ConfigValue::Integer(1), ConfigValue::Integer(2)]);
        assert!(matches!(arr_val, ConfigValue::Array(_)));

        let mut map = HashMap::new();
        map.insert("key".to_string(), ConfigValue::String("value".to_string()));
        let table_val = ConfigValue::Table(map);
        assert!(matches!(table_val, ConfigValue::Table(_)));
    }

    #[test]
    fn test_log_level_default() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn test_log_level_from_str() {
        assert_eq!("trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("info".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("error".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert!("invalid".parse::<LogLevel>().is_err());
    }

    #[test]
    fn test_log_format_default() {
        assert_eq!(LogFormat::default(), LogFormat::Json);
    }

    #[test]
    fn test_log_format_from_str() {
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
        assert_eq!("compact".parse::<LogFormat>().unwrap(), LogFormat::Compact);
        assert!("invalid".parse::<LogFormat>().is_err());
    }

    #[test]
    fn test_log_output_default() {
        assert_eq!(LogOutput::default(), LogOutput::Stdout);
    }

    #[test]
    fn test_log_output_from_str() {
        assert_eq!("stdout".parse::<LogOutput>().unwrap(), LogOutput::Stdout);
        assert_eq!("stderr".parse::<LogOutput>().unwrap(), LogOutput::Stderr);
        assert_eq!("file".parse::<LogOutput>().unwrap(), LogOutput::File);
        assert_eq!("both".parse::<LogOutput>().unwrap(), LogOutput::Both);
        assert!("invalid".parse::<LogOutput>().is_err());
    }

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0");
        assert_eq!(config.port, 9000);
        assert_eq!(config.quic_port, 9001);
        assert_eq!(config.max_connections, 1000);
        assert_eq!(config.connection_timeout_ms, 30000);
    }

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert!(config.data_dir.to_string_lossy().contains(".warp/data"));
        assert!(config.cache_dir.to_string_lossy().contains(".warp/cache"));
        assert_eq!(config.max_cache_size_bytes, 10 * 1024 * 1024 * 1024);
        assert_eq!(config.chunk_size, 1024 * 1024);
    }

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();
        assert_eq!(config.tick_interval_ms, 50);
        assert_eq!(config.max_concurrent_transfers, 100);
        assert_eq!(config.failover_timeout_ms, 5000);
        assert_eq!(config.use_gpu, true);
    }

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.level, LogLevel::Info);
        assert_eq!(config.format, LogFormat::Json);
        assert_eq!(config.output, LogOutput::Stdout);
        assert_eq!(config.file_path, None);
    }

    #[test]
    fn test_warp_config_default() {
        let config = WarpConfig::default();
        assert_eq!(config.network.port, 9000);
        assert_eq!(config.storage.chunk_size, 1024 * 1024);
        assert_eq!(config.scheduler.use_gpu, true);
        assert_eq!(config.log.level, LogLevel::Info);
    }

    #[test]
    fn test_config_loader_new() {
        let loader = ConfigLoader::new();
        assert_eq!(loader.sources.len(), 1);
        assert_eq!(loader.sources[0], ConfigSource::Default);
    }

    #[test]
    fn test_config_loader_with_file() {
        let loader = ConfigLoader::new().with_file("/etc/config.toml");
        assert_eq!(loader.sources.len(), 2);
    }

    #[test]
    fn test_config_loader_with_env_prefix() {
        let loader = ConfigLoader::new().with_env_prefix("WARP");
        assert_eq!(loader.env_prefix, Some("WARP".to_string()));
    }

    #[test]
    fn test_config_loader_default_config() {
        let config = ConfigLoader::default_config();
        assert_eq!(config.network.port, 9000);
    }

    #[test]
    fn test_config_loader_load_default() {
        let loader = ConfigLoader::new();
        let config = loader.load().unwrap();
        assert_eq!(config.network.port, 9000);
    }

    #[test]
    fn test_config_loader_load_from_str_minimal() {
        let toml = r#"
            [network]
            port = 8080
        "#;
        let config = ConfigLoader::load_from_str(toml).unwrap();
        assert_eq!(config.network.port, 8080);
    }

    #[test]
    fn test_config_loader_load_from_str_full() {
        let toml = r#"
            [network]
            bind_address = "127.0.0.1"
            port = 8080
            quic_port = 8081
            max_connections = 500
            connection_timeout_ms = 15000

            [storage]
            data_dir = "/data"
            cache_dir = "/cache"
            max_cache_size_bytes = 5368709120
            chunk_size = 524288

            [scheduler]
            tick_interval_ms = 100
            max_concurrent_transfers = 50
            failover_timeout_ms = 3000
            use_gpu = false

            [log]
            level = "debug"
            format = "pretty"
            output = "stderr"
        "#;
        let config = ConfigLoader::load_from_str(toml).unwrap();
        assert_eq!(config.network.bind_address, "127.0.0.1");
        assert_eq!(config.network.port, 8080);
        assert_eq!(config.storage.chunk_size, 524288);
        assert_eq!(config.scheduler.use_gpu, false);
        assert_eq!(config.log.level, LogLevel::Debug);
        assert_eq!(config.log.format, LogFormat::Pretty);
    }

    #[test]
    fn test_config_loader_load_from_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let toml = r#"
            [network]
            port = 7000
        "#;
        temp_file.write_all(toml.as_bytes()).unwrap();

        let loader = ConfigLoader::new().with_file(temp_file.path());
        let config = loader.load().unwrap();
        assert_eq!(config.network.port, 7000);
    }

    #[test]
    fn test_config_loader_load_missing_file() {
        let loader = ConfigLoader::new().with_file("/nonexistent/config.toml");
        assert!(loader.load().is_err());
    }

    #[test]
    fn test_config_loader_load_invalid_toml() {
        let result = ConfigLoader::load_from_str("invalid toml {{");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_loader_env_override_network_port() {
        // Use unique prefix to avoid parallel test interference
        unsafe {
            std::env::set_var("NETPORT_NETWORK_PORT", "9999");
        }
        let loader = ConfigLoader::new().with_env_prefix("NETPORT");
        let config = loader.load().unwrap();
        assert_eq!(config.network.port, 9999);
        unsafe {
            std::env::remove_var("NETPORT_NETWORK_PORT");
        }
    }

    #[test]
    fn test_config_loader_env_override_storage_data_dir() {
        // Use unique prefix to avoid parallel test interference
        unsafe {
            std::env::set_var("STORDIR_STORAGE_DATA_DIR", "/custom/data");
        }
        let loader = ConfigLoader::new().with_env_prefix("STORDIR");
        let config = loader.load().unwrap();
        assert_eq!(config.storage.data_dir, PathBuf::from("/custom/data"));
        unsafe {
            std::env::remove_var("STORDIR_STORAGE_DATA_DIR");
        }
    }

    #[test]
    fn test_config_loader_env_override_log_level() {
        // Use unique prefix to avoid parallel test interference
        unsafe {
            std::env::set_var("LOGLVL_LOG_LEVEL", "error");
        }
        let loader = ConfigLoader::new().with_env_prefix("LOGLVL");
        let config = loader.load().unwrap();
        assert_eq!(config.log.level, LogLevel::Error);
        unsafe {
            std::env::remove_var("LOGLVL_LOG_LEVEL");
        }
    }

    #[test]
    fn test_config_loader_env_override_invalid_port() {
        // Use unique prefix to avoid parallel test interference
        unsafe {
            std::env::set_var("INVPORT_NETWORK_PORT", "invalid");
        }
        let loader = ConfigLoader::new().with_env_prefix("INVPORT");
        assert!(loader.load().is_err());
        unsafe {
            std::env::remove_var("INVPORT_NETWORK_PORT");
        }
    }

    #[test]
    fn test_config_loader_env_override_bool() {
        // Use unique prefix to avoid parallel test interference
        unsafe {
            std::env::set_var("BOOLTEST_SCHEDULER_USE_GPU", "false");
        }
        let loader = ConfigLoader::new().with_env_prefix("BOOLTEST");
        let config = loader.load().unwrap();
        assert_eq!(config.scheduler.use_gpu, false);
        unsafe {
            std::env::remove_var("BOOLTEST_SCHEDULER_USE_GPU");
        }
    }

    #[test]
    fn test_path_expansion_tilde() {
        let path = PathBuf::from("~/test/path");
        let expanded = ConfigLoader::expand_path(&path);
        assert!(!expanded.to_string_lossy().contains('~'));
    }

    #[test]
    fn test_path_expansion_absolute() {
        let path = PathBuf::from("/absolute/path");
        let expanded = ConfigLoader::expand_path(&path);
        assert_eq!(expanded, path);
    }

    #[test]
    fn test_toml_serialization_roundtrip() {
        let config = WarpConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: WarpConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.network.port, config.network.port);
    }

    #[test]
    fn test_config_loader_file_overrides_env() {
        // Use unique prefix to avoid parallel test interference
        unsafe {
            std::env::set_var("FILEOVR_NETWORK_PORT", "8888");
        }

        let mut temp_file = NamedTempFile::new().unwrap();
        let toml = r#"
            [network]
            port = 7777
        "#;
        temp_file.write_all(toml.as_bytes()).unwrap();

        let loader = ConfigLoader::new()
            .with_env_prefix("FILEOVR")
            .with_file(temp_file.path());
        let config = loader.load().unwrap();

        // File should override env
        assert_eq!(config.network.port, 7777);
        unsafe {
            std::env::remove_var("FILEOVR_NETWORK_PORT");
        }
    }

    #[test]
    fn test_config_loader_env_overrides_default() {
        // Use unique prefix to avoid parallel test interference
        unsafe {
            std::env::set_var("ENVDEF_NETWORK_PORT", "8888");
        }
        let loader = ConfigLoader::new().with_env_prefix("ENVDEF");
        let config = loader.load().unwrap();
        assert_eq!(config.network.port, 8888);
        unsafe {
            std::env::remove_var("ENVDEF_NETWORK_PORT");
        }
    }

    #[test]
    fn test_config_loader_multiple_env_overrides() {
        // Use unique prefix to avoid parallel test interference
        unsafe {
            std::env::set_var("MULTI_NETWORK_PORT", "8888");
            std::env::set_var("MULTI_NETWORK_QUIC_PORT", "8889");
            std::env::set_var("MULTI_LOG_LEVEL", "debug");
        }

        let loader = ConfigLoader::new().with_env_prefix("MULTI");
        let config = loader.load().unwrap();

        assert_eq!(config.network.port, 8888);
        assert_eq!(config.network.quic_port, 8889);
        assert_eq!(config.log.level, LogLevel::Debug);

        unsafe {
            std::env::remove_var("MULTI_NETWORK_PORT");
            std::env::remove_var("MULTI_NETWORK_QUIC_PORT");
            std::env::remove_var("MULTI_LOG_LEVEL");
        }
    }
}
