//! Configuration validation for warp-portal

use crate::config::{
    LogConfig, LogOutput, NetworkConfig, SchedulerConfig, StorageConfig, WarpConfig,
};
use std::fmt;

/// Result of configuration validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// List of validation errors that prevent the configuration from being used
    pub errors: Vec<ValidationError>,
    /// List of non-blocking warnings about potential configuration issues
    pub warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    /// Creates a new empty validation result
    #[must_use]
    pub const fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Returns true if there are no validation errors
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Returns true if there are any warnings present
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Adds a validation error to the result
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Adds a validation warning to the result
    pub fn add_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning);
    }

    /// Merges another validation result into this one
    pub fn merge(&mut self, other: Self) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Validation error details
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// The configuration field that failed validation
    pub field: String,
    /// Human-readable error message
    pub message: String,
    /// Error classification code
    pub code: ErrorCode,
}

impl ValidationError {
    /// Creates a new validation error
    pub fn new(field: impl Into<String>, message: impl Into<String>, code: ErrorCode) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            code,
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}: {}", self.code, self.field, self.message)
    }
}

/// Validation warning details
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationWarning {
    /// The configuration field that triggered the warning
    pub field: String,
    /// Human-readable warning message
    pub message: String,
    /// Optional suggestion for resolving the warning
    pub suggestion: Option<String>,
}

impl ValidationWarning {
    /// Creates a new validation warning without a suggestion
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            suggestion: None,
        }
    }

    /// Creates a new validation warning with a suggestion for resolution
    pub fn with_suggestion(
        field: impl Into<String>,
        message: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            suggestion: Some(suggestion.into()),
        }
    }
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[WARNING] {}: {}", self.field, self.message)?;
        if let Some(ref s) = self.suggestion {
            write!(f, " (Suggestion: {s})")?;
        }
        Ok(())
    }
}

/// Error code classifications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// A required field is missing or empty
    Required,
    /// A value is outside the acceptable range
    OutOfRange,
    /// A value has an invalid format
    InvalidFormat,
    /// A specified path does not exist
    PathNotFound,
    /// Insufficient permissions to access a resource
    PermissionDenied,
    /// Configuration values are in conflict with each other
    Conflict,
    /// A deprecated configuration option is being used
    Deprecated,
}

/// Main configuration validator
#[derive(Debug)]
pub struct Validator {
    /// Whether to enable strict validation with additional warnings
    strict_mode: bool,
}

impl Validator {
    /// Creates a new validator with default settings
    #[must_use]
    pub const fn new() -> Self {
        Self { strict_mode: false }
    }

    /// Enables or disables strict validation mode
    #[must_use]
    pub const fn with_strict_mode(mut self, enabled: bool) -> Self {
        self.strict_mode = enabled;
        self
    }

    /// Validates a complete `WarpConfig` and returns the result
    #[must_use]
    pub fn validate(&self, config: &WarpConfig) -> ValidationResult {
        let mut result = ValidationResult::new();
        result.merge(self.validate_network(&config.network));
        result.merge(self.validate_storage(&config.storage));
        result.merge(self.validate_scheduler(&config.scheduler));
        result.merge(self.validate_log(&config.log));

        let consistency_rule = ConsistencyRule;
        for error in consistency_rule.validate(config) {
            result.add_error(error);
        }
        result
    }

    /// Validates network configuration settings
    #[must_use]
    pub fn validate_network(&self, config: &NetworkConfig) -> ValidationResult {
        let mut result = ValidationResult::new();

        let port_rule = PortRangeRule;
        for error in port_rule.validate_ports(config.quic_port, config.port) {
            result.add_error(error);
        }

        let resource_rule = ResourceLimitRule;
        if let Some(error) = resource_rule.validate_max_connections(config.max_connections) {
            result.add_error(error);
        }

        if config.connection_timeout_ms == 0 {
            result.add_error(ValidationError::new(
                "network.connection_timeout_ms",
                "Connection timeout must be greater than 0",
                ErrorCode::OutOfRange,
            ));
        }

        if self.strict_mode && config.max_connections > 5000 {
            result.add_warning(ValidationWarning::with_suggestion(
                "network.max_connections",
                format!("High connection limit: {}", config.max_connections),
                "Consider if this many connections are necessary",
            ));
        }
        result
    }

    /// Validates storage configuration settings
    #[must_use]
    pub fn validate_storage(&self, config: &StorageConfig) -> ValidationResult {
        let mut result = ValidationResult::new();

        let path_rule = PathExistsRule;
        result.merge(path_rule.validate_paths(config));

        if !config.chunk_size.is_power_of_two() {
            result.add_error(ValidationError::new(
                "storage.chunk_size",
                format!("Chunk size {} is not a power of 2", config.chunk_size),
                ErrorCode::InvalidFormat,
            ));
        }

        if config.chunk_size < 4096 {
            result.add_error(ValidationError::new(
                "storage.chunk_size",
                "Chunk size must be at least 4096 bytes",
                ErrorCode::OutOfRange,
            ));
        }

        if config.chunk_size > 16 * 1024 * 1024 {
            result.add_error(ValidationError::new(
                "storage.chunk_size",
                "Chunk size must not exceed 16 MB",
                ErrorCode::OutOfRange,
            ));
        }

        let resource_rule = ResourceLimitRule;
        if let Some(warning) = resource_rule.validate_cache_size(config.max_cache_size_bytes) {
            result.add_warning(warning);
        }

        result
    }

    /// Validates scheduler configuration settings
    #[must_use]
    pub fn validate_scheduler(&self, config: &SchedulerConfig) -> ValidationResult {
        let mut result = ValidationResult::new();

        let resource_rule = ResourceLimitRule;
        if let Some(error) =
            resource_rule.validate_concurrent_transfers(config.max_concurrent_transfers)
        {
            result.add_error(error);
        }

        if config.tick_interval_ms == 0 {
            result.add_error(ValidationError::new(
                "scheduler.tick_interval_ms",
                "Tick interval must be greater than 0",
                ErrorCode::OutOfRange,
            ));
        }

        if config.failover_timeout_ms == 0 {
            result.add_error(ValidationError::new(
                "scheduler.failover_timeout_ms",
                "Failover timeout must be greater than 0",
                ErrorCode::OutOfRange,
            ));
        }

        if config.use_gpu {
            result.add_warning(ValidationWarning::with_suggestion(
                "scheduler.use_gpu",
                "GPU acceleration is enabled",
                "Ensure GPU drivers and CUDA are properly installed",
            ));
        }
        result
    }

    /// Validates logging configuration settings
    #[must_use]
    pub fn validate_log(&self, config: &LogConfig) -> ValidationResult {
        let mut result = ValidationResult::new();

        // LogLevel is now an enum, so no validation needed

        if (config.output == LogOutput::File || config.output == LogOutput::Both)
            && config.file_path.is_none()
        {
            result.add_error(ValidationError::new(
                "log.file_path",
                "file_path must be set when output is 'file' or 'both'",
                ErrorCode::Required,
            ));
        }

        if let Some(ref path) = config.file_path {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    result.add_error(ValidationError::new(
                        "log.file_path",
                        format!("Parent directory does not exist: {}", parent.display()),
                        ErrorCode::PathNotFound,
                    ));
                }
            }
        }
        result
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for custom validation rules
pub trait ValidationRule {
    /// Validates the configuration and returns a list of errors
    fn validate(&self, config: &WarpConfig) -> Vec<ValidationError>;
    /// Returns the name of this validation rule
    fn name(&self) -> &str;
}

/// Port range validation rule
pub struct PortRangeRule;

impl PortRangeRule {
    /// Validates that ports are not privileged and do not conflict
    #[must_use]
    pub fn validate_ports(&self, quic_port: u16, http_port: u16) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if quic_port <= 1024 {
            errors.push(ValidationError::new(
                "network.quic_port",
                format!("Port {quic_port} is privileged. Must be > 1024"),
                ErrorCode::OutOfRange,
            ));
        }

        if http_port <= 1024 {
            errors.push(ValidationError::new(
                "network.port",
                format!("Port {http_port} is privileged. Must be > 1024"),
                ErrorCode::OutOfRange,
            ));
        }

        if quic_port == http_port {
            errors.push(ValidationError::new(
                "network",
                format!("QUIC port and HTTP port cannot be the same: {quic_port}"),
                ErrorCode::Conflict,
            ));
        }
        errors
    }
}

impl ValidationRule for PortRangeRule {
    fn validate(&self, config: &WarpConfig) -> Vec<ValidationError> {
        self.validate_ports(config.network.quic_port, config.network.port)
    }

    fn name(&self) -> &'static str {
        "PortRangeRule"
    }
}

/// Path existence validation rule
pub struct PathExistsRule;

impl PathExistsRule {
    /// Validates that storage paths exist and are accessible
    #[must_use]
    pub fn validate_paths(&self, config: &StorageConfig) -> ValidationResult {
        let mut result = ValidationResult::new();

        if config.data_dir.exists() {
            match std::fs::metadata(&config.data_dir) {
                Ok(metadata) => {
                    if metadata.permissions().readonly() {
                        result.add_error(ValidationError::new(
                            "storage.data_dir",
                            format!("Data directory is readonly: {}", config.data_dir.display()),
                            ErrorCode::PermissionDenied,
                        ));
                    }
                }
                Err(_) => {
                    result.add_error(ValidationError::new(
                        "storage.data_dir",
                        format!(
                            "Cannot access data directory: {}",
                            config.data_dir.display()
                        ),
                        ErrorCode::PermissionDenied,
                    ));
                }
            }
        } else if let Some(parent) = config.data_dir.parent() {
            if parent.exists() {
                match std::fs::metadata(parent) {
                    Ok(metadata) => {
                        if metadata.permissions().readonly() {
                            result.add_error(ValidationError::new(
                                "storage.data_dir",
                                format!(
                                    "Cannot create data directory, parent is readonly: {}",
                                    parent.display()
                                ),
                                ErrorCode::PermissionDenied,
                            ));
                        } else {
                            result.add_warning(ValidationWarning::with_suggestion(
                                "storage.data_dir",
                                format!(
                                    "Data directory does not exist: {}",
                                    config.data_dir.display()
                                ),
                                "Directory will be created on first use",
                            ));
                        }
                    }
                    Err(_) => {
                        result.add_error(ValidationError::new(
                            "storage.data_dir",
                            format!("Cannot access parent directory: {}", parent.display()),
                            ErrorCode::PermissionDenied,
                        ));
                    }
                }
            } else {
                result.add_error(ValidationError::new(
                    "storage.data_dir",
                    format!("Data directory parent does not exist: {}", parent.display()),
                    ErrorCode::PathNotFound,
                ));
            }
        }

        if !config.cache_dir.exists() {
            if let Some(parent) = config.cache_dir.parent() {
                if parent.exists() {
                    result.add_warning(ValidationWarning::with_suggestion(
                        "storage.cache_dir",
                        format!(
                            "Cache directory does not exist: {}",
                            config.cache_dir.display()
                        ),
                        "Directory will be created on first use",
                    ));
                } else {
                    result.add_error(ValidationError::new(
                        "storage.cache_dir",
                        format!(
                            "Cache directory parent does not exist: {}",
                            parent.display()
                        ),
                        ErrorCode::PathNotFound,
                    ));
                }
            }
        }
        result
    }
}

impl ValidationRule for PathExistsRule {
    fn validate(&self, config: &WarpConfig) -> Vec<ValidationError> {
        self.validate_paths(&config.storage).errors
    }

    fn name(&self) -> &'static str {
        "PathExistsRule"
    }
}

/// Resource limit validation rule
pub struct ResourceLimitRule;

impl ResourceLimitRule {
    /// Validates that max connections is within acceptable limits
    #[must_use]
    pub fn validate_max_connections(&self, max_connections: usize) -> Option<ValidationError> {
        if max_connections > 10000 {
            Some(ValidationError::new(
                "network.max_connections",
                format!("Max connections {max_connections} exceeds limit of 10000"),
                ErrorCode::OutOfRange,
            ))
        } else if max_connections == 0 {
            Some(ValidationError::new(
                "network.max_connections",
                "Max connections must be greater than 0",
                ErrorCode::OutOfRange,
            ))
        } else {
            None
        }
    }

    /// Validates cache size and warns if it exceeds recommended limits
    #[must_use]
    pub fn validate_cache_size(&self, cache_size: u64) -> Option<ValidationWarning> {
        let gb_100 = 100u64 * 1024 * 1024 * 1024;
        if cache_size > gb_100 {
            Some(ValidationWarning::with_suggestion(
                "storage.max_cache_size_bytes",
                format!("Large cache size: {} GB", cache_size / (1024 * 1024 * 1024)),
                "Ensure sufficient disk space is available",
            ))
        } else {
            None
        }
    }

    /// Validates that max concurrent transfers is within acceptable limits
    #[must_use]
    pub fn validate_concurrent_transfers(&self, max_transfers: usize) -> Option<ValidationError> {
        if max_transfers > 1000 {
            Some(ValidationError::new(
                "scheduler.max_concurrent_transfers",
                format!("Max concurrent transfers {max_transfers} exceeds limit of 1000"),
                ErrorCode::OutOfRange,
            ))
        } else if max_transfers == 0 {
            Some(ValidationError::new(
                "scheduler.max_concurrent_transfers",
                "Max concurrent transfers must be greater than 0",
                ErrorCode::OutOfRange,
            ))
        } else {
            None
        }
    }
}

impl ValidationRule for ResourceLimitRule {
    fn validate(&self, config: &WarpConfig) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(error) = self.validate_max_connections(config.network.max_connections) {
            errors.push(error);
        }
        if let Some(error) =
            self.validate_concurrent_transfers(config.scheduler.max_concurrent_transfers)
        {
            errors.push(error);
        }
        errors
    }

    fn name(&self) -> &'static str {
        "ResourceLimitRule"
    }
}

/// Consistency validation rule
pub struct ConsistencyRule;

impl ConsistencyRule {
    /// Checks for configuration inconsistencies across different sections
    fn check_consistency(&self, config: &WarpConfig) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if config.log.output == LogOutput::File && config.log.file_path.is_none() {
            errors.push(ValidationError::new(
                "log",
                "Log output is 'file' but file_path is not set",
                ErrorCode::Conflict,
            ));
        }

        if !config.storage.chunk_size.is_power_of_two() {
            errors.push(ValidationError::new(
                "storage.chunk_size",
                "Chunk size must be a power of 2",
                ErrorCode::InvalidFormat,
            ));
        }
        errors
    }
}

impl ValidationRule for ConsistencyRule {
    fn validate(&self, config: &WarpConfig) -> Vec<ValidationError> {
        self.check_consistency(config)
    }

    fn name(&self) -> &'static str {
        "ConsistencyRule"
    }
}

/// Custom validator with pluggable rules
pub struct CustomValidator {
    /// Collection of validation rules to apply
    rules: Vec<Box<dyn ValidationRule>>,
}

impl CustomValidator {
    /// Creates a new custom validator with no rules
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Adds a validation rule to this validator
    #[must_use]
    pub fn add_rule(mut self, rule: Box<dyn ValidationRule>) -> Self {
        self.rules.push(rule);
        self
    }

    /// Validates the configuration using all registered rules
    #[must_use]
    pub fn validate(&self, config: &WarpConfig) -> ValidationResult {
        let mut result = ValidationResult::new();
        for rule in &self.rules {
            for error in rule.validate(config) {
                result.add_error(error);
            }
        }
        result
    }
}

impl Default for CustomValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validation_result_operations() {
        let mut result = ValidationResult::new();
        assert!(result.is_valid());
        assert!(!result.has_warnings());

        result.add_error(ValidationError::new("test", "error", ErrorCode::Required));
        assert!(!result.is_valid());

        result.add_warning(ValidationWarning::new("test", "warning"));
        assert!(result.has_warnings());
    }

    #[test]
    fn test_validation_error_and_warning() {
        let error = ValidationError::new("field", "message", ErrorCode::Required);
        assert_eq!(error.field, "field");
        assert_eq!(error.code, ErrorCode::Required);
        assert!(format!("{}", error).contains("field"));

        let warning = ValidationWarning::new("field", "message");
        assert_eq!(warning.field, "field");
        assert!(warning.suggestion.is_none());

        let warning2 = ValidationWarning::with_suggestion("field", "message", "suggestion");
        assert_eq!(warning2.suggestion, Some("suggestion".to_string()));
    }

    #[test]
    fn test_error_code_variants() {
        let codes = [
            ErrorCode::Required,
            ErrorCode::OutOfRange,
            ErrorCode::InvalidFormat,
            ErrorCode::PathNotFound,
            ErrorCode::PermissionDenied,
            ErrorCode::Conflict,
            ErrorCode::Deprecated,
        ];
        for code in &codes {
            let _ = ValidationError::new("field", "msg", *code);
        }
    }

    #[test]
    fn test_validator_modes() {
        let validator = Validator::new();
        assert!(!validator.strict_mode);
        let strict = Validator::new().with_strict_mode(true);
        assert!(strict.strict_mode);
    }

    #[test]
    fn test_network_validation_valid() {
        let validator = Validator::new();
        let result = validator.validate_network(&NetworkConfig::default());
        assert!(result.is_valid());
    }

    #[test]
    fn test_network_validation_errors() {
        let validator = Validator::new();

        let mut config = NetworkConfig::default();
        config.quic_port = 80;
        assert!(!validator.validate_network(&config).is_valid());

        config = NetworkConfig::default();
        config.quic_port = 8080;
        config.port = 8080;
        assert!(!validator.validate_network(&config).is_valid());

        config = NetworkConfig::default();
        config.max_connections = 15000;
        assert!(!validator.validate_network(&config).is_valid());

        config = NetworkConfig::default();
        config.max_connections = 0;
        assert!(!validator.validate_network(&config).is_valid());
    }

    #[test]
    fn test_storage_validation_chunk_size_errors() {
        let validator = Validator::new();

        let mut config = StorageConfig::default();
        config.chunk_size = 1000;
        assert!(!validator.validate_storage(&config).is_valid());

        config = StorageConfig::default();
        config.chunk_size = 2048;
        assert!(!validator.validate_storage(&config).is_valid());

        config = StorageConfig::default();
        config.chunk_size = 32 * 1024 * 1024;
        assert!(!validator.validate_storage(&config).is_valid());
    }

    #[test]
    fn test_storage_validation_valid_paths() {
        let temp_dir = TempDir::new().unwrap();
        let validator = Validator::new();
        let mut config = StorageConfig::default();
        config.data_dir = temp_dir.path().join("data");
        config.cache_dir = temp_dir.path().join("cache");
        let result = validator.validate_storage(&config);
        assert!(result.is_valid());
        assert!(result.has_warnings());
    }

    #[test]
    fn test_storage_validation_invalid_data_dir() {
        let validator = Validator::new();
        let mut config = StorageConfig::default();
        config.data_dir = "/nonexistent/invalid/path/data".into();
        let result = validator.validate_storage(&config);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_scheduler_validation_valid() {
        let validator = Validator::new();
        let result = validator.validate_scheduler(&SchedulerConfig::default());
        assert!(result.is_valid());
    }

    #[test]
    fn test_scheduler_validation_errors() {
        let validator = Validator::new();

        let mut config = SchedulerConfig::default();
        config.max_concurrent_transfers = 2000;
        assert!(!validator.validate_scheduler(&config).is_valid());

        config = SchedulerConfig::default();
        config.max_concurrent_transfers = 0;
        assert!(!validator.validate_scheduler(&config).is_valid());

        config = SchedulerConfig::default();
        config.tick_interval_ms = 0;
        assert!(!validator.validate_scheduler(&config).is_valid());
    }

    #[test]
    fn test_log_validation_valid() {
        let validator = Validator::new();
        let result = validator.validate_log(&LogConfig::default());
        assert!(result.is_valid());
    }

    #[test]
    fn test_log_validation_errors() {
        let validator = Validator::new();

        let mut config = LogConfig::default();
        config.output = LogOutput::Both;
        config.file_path = None;
        assert!(!validator.validate_log(&config).is_valid());

        config = LogConfig::default();
        config.output = LogOutput::File;
        config.file_path = None;
        assert!(!validator.validate_log(&config).is_valid());

        config = LogConfig::default();
        config.output = LogOutput::File;
        config.file_path = Some("/nonexistent/path/log.txt".into());
        assert!(!validator.validate_log(&config).is_valid());
    }

    #[test]
    fn test_strict_mode_vs_normal() {
        let normal = Validator::new();
        let strict = Validator::new().with_strict_mode(true);
        let mut config = NetworkConfig::default();
        config.max_connections = 6000;
        assert!(normal.validate_network(&config).is_valid());
        assert!(strict.validate_network(&config).has_warnings());
    }

    #[test]
    fn test_custom_validation_rules() {
        let validator = CustomValidator::new()
            .add_rule(Box::new(PortRangeRule))
            .add_rule(Box::new(ResourceLimitRule));
        let mut config = WarpConfig::default();
        config.network.quic_port = 80;
        let result = validator.validate(&config);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_multiple_errors_accumulated() {
        let validator = Validator::new();
        let mut config = NetworkConfig::default();
        config.quic_port = 80;
        config.port = 443;
        config.max_connections = 0;
        let result = validator.validate_network(&config);
        assert!(result.errors.len() >= 3);
    }

    #[test]
    fn test_warning_generation() {
        let validator = Validator::new();
        let mut config = SchedulerConfig::default();
        config.use_gpu = true;
        let result = validator.validate_scheduler(&config);
        assert!(result.has_warnings());
    }

    #[test]
    fn test_path_existence_checking() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().join("data");
        fs::create_dir(&data_dir).unwrap();
        let validator = Validator::new();
        let mut config = StorageConfig::default();
        config.data_dir = data_dir;
        config.cache_dir = temp_dir.path().join("cache");
        let result = validator.validate_storage(&config);
        assert!(result.is_valid());
    }

    #[test]
    fn test_resource_limit_warnings() {
        let validator = Validator::new();
        let mut config = StorageConfig::default();
        config.max_cache_size_bytes = 150 * 1024 * 1024 * 1024;
        let result = validator.validate_storage(&config);
        assert!(result.has_warnings());
    }

    #[test]
    fn test_full_config_validation() {
        let temp_dir = TempDir::new().unwrap();
        let validator = Validator::new();
        let mut config = WarpConfig::default();
        // Use temp dir to avoid path errors
        config.storage.data_dir = temp_dir.path().join("data");
        config.storage.cache_dir = temp_dir.path().join("cache");
        let result = validator.validate(&config);
        // Should be valid but may have warnings about non-existent directories
        assert!(result.is_valid());
    }

    #[test]
    fn test_full_config_validation_with_errors() {
        let validator = Validator::new();
        let mut config = WarpConfig::default();
        config.network.quic_port = 80;
        config.storage.chunk_size = 1000;
        config.log.output = LogOutput::File;
        let result = validator.validate(&config);
        assert!(!result.is_valid());
        assert!(result.errors.len() >= 3);
    }

    #[test]
    fn test_validation_result_merging() {
        let mut r1 = ValidationResult::new();
        r1.add_error(ValidationError::new("f1", "e1", ErrorCode::Required));
        let mut r2 = ValidationResult::new();
        r2.add_error(ValidationError::new("f2", "e2", ErrorCode::OutOfRange));
        r1.merge(r2);
        assert_eq!(r1.errors.len(), 2);
    }

    #[test]
    fn test_port_range_rule() {
        let rule = PortRangeRule;
        assert!(!rule.validate_ports(80, 8080).is_empty());
        assert!(rule.validate_ports(8080, 8081).is_empty());
    }

    #[test]
    fn test_consistency_rule() {
        let rule = ConsistencyRule;
        let mut config = WarpConfig::default();
        config.log.output = LogOutput::File;
        config.log.file_path = None;
        let errors = rule.validate(&config);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_validation_rule_trait() {
        assert_eq!(PortRangeRule.name(), "PortRangeRule");
        assert_eq!(PathExistsRule.name(), "PathExistsRule");
        assert_eq!(ResourceLimitRule.name(), "ResourceLimitRule");
        assert_eq!(ConsistencyRule.name(), "ConsistencyRule");
    }

    #[test]
    fn test_connection_timeout_zero() {
        let validator = Validator::new();
        let mut config = NetworkConfig::default();
        config.connection_timeout_ms = 0;
        let result = validator.validate_network(&config);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_log_output_variants() {
        assert_eq!(LogOutput::Stdout, LogOutput::Stdout);
        assert_ne!(LogOutput::Stdout, LogOutput::Stderr);
    }
}
