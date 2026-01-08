//! Structured Logging with Tracing

use crate::{Result, TelemetryError};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tracing::Level;
use tracing_subscriber::EnvFilter;

/// Log levels compatible with tracing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    /// Trace-level logging for very verbose output
    Trace,
    /// Debug-level logging for diagnostic information
    Debug,
    /// Info-level logging for general informational messages
    Info,
    /// Warn-level logging for warning messages
    Warn,
    /// Error-level logging for error conditions
    Error,
}

impl LogLevel {
    /// Convert to tracing Level
    #[must_use]
    pub const fn to_tracing_level(&self) -> Level {
        match self {
            Self::Trace => Level::TRACE,
            Self::Debug => Level::DEBUG,
            Self::Info => Level::INFO,
            Self::Warn => Level::WARN,
            Self::Error => Level::ERROR,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Trace => "trace",
                Self::Debug => "debug",
                Self::Info => "info",
                Self::Warn => "warn",
                Self::Error => "error",
            }
        )
    }
}

impl FromStr for LogLevel {
    type Err = TelemetryError;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            _ => Err(TelemetryError::Logging(format!("Invalid log level: {s}"))),
        }
    }
}

/// Output format for logs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// JSON formatted output
    Json,
    /// Human-readable pretty format with colors
    Pretty,
    /// Compact format with minimal spacing
    Compact,
}

/// Output destination for logs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogOutput {
    /// Write logs to standard output
    Stdout,
    /// Write logs to standard error
    Stderr,
    /// Write logs to a file at the specified path
    File(PathBuf),
    /// Write logs to both standard output and a file
    Both {
        /// Whether to write to stdout
        stdout: bool,
        /// File path for log output
        file: PathBuf,
    },
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Minimum log level to display
    pub level: LogLevel,
    /// Format for log output
    pub format: LogFormat,
    /// Destination for log output
    pub output: LogOutput,
    /// Whether to include the target module path in logs
    pub include_target: bool,
    /// Whether to include file name and line number in logs
    pub include_file_line: bool,
    /// Whether to include thread ID in logs
    pub include_thread_id: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            output: LogOutput::Stdout,
            include_target: true,
            include_file_line: false,
            include_thread_id: false,
        }
    }
}

/// Contextual information for logging
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogContext {
    /// Component name generating the log
    pub component: String,
    /// Optional transfer identifier for tracking
    pub transfer_id: Option<String>,
    /// Optional edge identifier for tracking
    pub edge_id: Option<String>,
    /// Additional arbitrary key-value pairs
    pub extra: HashMap<String, String>,
}

impl LogContext {
    /// Creates a new log context with the specified component name
    pub fn new(component: impl Into<String>) -> Self {
        Self {
            component: component.into(),
            transfer_id: None,
            edge_id: None,
            extra: HashMap::new(),
        }
    }

    /// Adds a transfer ID to the context
    #[must_use]
    pub fn with_transfer_id(mut self, id: impl Into<String>) -> Self {
        self.transfer_id = Some(id.into());
        self
    }

    /// Adds an edge ID to the context
    #[must_use]
    pub fn with_edge_id(mut self, id: impl Into<String>) -> Self {
        self.edge_id = Some(id.into());
        self
    }

    /// Adds a custom field to the context
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.insert(key.into(), value.into());
        self
    }
}

/// Structured logger
pub struct StructuredLogger {
    config: LogConfig,
    context: Arc<Mutex<Option<LogContext>>>,
}

impl StructuredLogger {
    /// Creates a new structured logger with the given configuration
    ///
    /// # Errors
    ///
    /// Currently never returns an error, but may fail in future versions.
    pub fn new(config: LogConfig) -> Result<Self> {
        Ok(Self {
            config,
            context: Arc::new(Mutex::new(None)),
        })
    }

    /// Initializes the global logging system with this logger's configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the logging subscriber fails to initialize or if file operations fail.
    pub fn init(&self) -> Result<()> {
        init_logging(&self.config)
    }

    /// Creates a new logger instance with the specified context
    #[must_use]
    pub fn with_context(&self, ctx: LogContext) -> Self {
        Self {
            config: self.config.clone(),
            context: Arc::new(Mutex::new(Some(ctx))),
        }
    }

    /// Logs a trace-level message
    pub fn trace(&self, msg: &str) {
        self.log(LogLevel::Trace, msg);
    }

    /// Logs a debug-level message
    pub fn debug(&self, msg: &str) {
        self.log(LogLevel::Debug, msg);
    }

    /// Logs an info-level message
    pub fn info(&self, msg: &str) {
        self.log(LogLevel::Info, msg);
    }

    /// Logs a warn-level message
    pub fn warn(&self, msg: &str) {
        self.log(LogLevel::Warn, msg);
    }

    /// Logs an error-level message
    pub fn error(&self, msg: &str) {
        self.log(LogLevel::Error, msg);
    }

    fn log(&self, level: LogLevel, msg: &str) {
        let ctx = self.context.lock();
        if let Some(ref context) = *ctx {
            log_with_context(level, msg, context);
        } else {
            log_plain(level, msg);
        }
    }

    /// Logs an event with additional structured fields
    pub fn event(&self, level: LogLevel, msg: &str, fields: &[(&str, &str)]) {
        let ctx = self.context.lock();
        if let Some(ref context) = *ctx {
            log_event_with_context(level, msg, fields, context);
        } else {
            log_event_plain(level, msg, fields);
        }
    }
}

fn log_with_context(level: LogLevel, msg: &str, ctx: &LogContext) {
    match level {
        LogLevel::Trace => tracing::trace!(
            component = ctx.component,
            transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(),
            "{}",
            msg
        ),
        LogLevel::Debug => tracing::debug!(
            component = ctx.component,
            transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(),
            "{}",
            msg
        ),
        LogLevel::Info => tracing::info!(
            component = ctx.component,
            transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(),
            "{}",
            msg
        ),
        LogLevel::Warn => tracing::warn!(
            component = ctx.component,
            transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(),
            "{}",
            msg
        ),
        LogLevel::Error => tracing::error!(
            component = ctx.component,
            transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(),
            "{}",
            msg
        ),
    }
}

fn log_plain(level: LogLevel, msg: &str) {
    match level {
        LogLevel::Trace => tracing::trace!("{}", msg),
        LogLevel::Debug => tracing::debug!("{}", msg),
        LogLevel::Info => tracing::info!("{}", msg),
        LogLevel::Warn => tracing::warn!("{}", msg),
        LogLevel::Error => tracing::error!("{}", msg),
    }
}

fn log_event_with_context(level: LogLevel, msg: &str, fields: &[(&str, &str)], ctx: &LogContext) {
    match level {
        LogLevel::Trace => tracing::trace!(
            component = ctx.component, transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(), fields = ?fields, "{}", msg
        ),
        LogLevel::Debug => tracing::debug!(
            component = ctx.component, transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(), fields = ?fields, "{}", msg
        ),
        LogLevel::Info => tracing::info!(
            component = ctx.component, transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(), fields = ?fields, "{}", msg
        ),
        LogLevel::Warn => tracing::warn!(
            component = ctx.component, transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(), fields = ?fields, "{}", msg
        ),
        LogLevel::Error => tracing::error!(
            component = ctx.component, transfer_id = ctx.transfer_id.as_deref(),
            edge_id = ctx.edge_id.as_deref(), fields = ?fields, "{}", msg
        ),
    }
}

fn log_event_plain(level: LogLevel, msg: &str, fields: &[(&str, &str)]) {
    match level {
        LogLevel::Trace => tracing::trace!(fields = ?fields, "{}", msg),
        LogLevel::Debug => tracing::debug!(fields = ?fields, "{}", msg),
        LogLevel::Info => tracing::info!(fields = ?fields, "{}", msg),
        LogLevel::Warn => tracing::warn!(fields = ?fields, "{}", msg),
        LogLevel::Error => tracing::error!(fields = ?fields, "{}", msg),
    }
}

/// Builder for structured logs
pub struct LogBuilder {
    /// Log level for the message
    level: LogLevel,
    /// Optional message text
    message: Option<String>,
    /// Additional structured fields
    fields: Vec<(String, String)>,
    /// Optional logging context
    context: Option<LogContext>,
}

impl LogBuilder {
    /// Creates a new log builder with the specified level
    #[must_use]
    pub const fn new(level: LogLevel) -> Self {
        Self {
            level,
            message: None,
            fields: Vec::new(),
            context: None,
        }
    }

    /// Sets the message text for the log
    #[must_use]
    pub fn message(mut self, msg: &str) -> Self {
        self.message = Some(msg.to_string());
        self
    }

    /// Adds a structured field to the log
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn field(mut self, key: &str, value: impl ToString) -> Self {
        self.fields.push((key.to_string(), value.to_string()));
        self
    }

    /// Sets the logging context
    #[must_use]
    pub fn context(mut self, ctx: &LogContext) -> Self {
        self.context = Some(ctx.clone());
        self
    }

    /// Emits the log message with all configured fields
    pub fn emit(self) {
        let msg = self.message.unwrap_or_default();
        if let Some(ref ctx) = self.context {
            log_event_with_context(
                self.level,
                &msg,
                &self
                    .fields
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect::<Vec<_>>(),
                ctx,
            );
        } else {
            log_event_plain(
                self.level,
                &msg,
                &self
                    .fields
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect::<Vec<_>>(),
            );
        }
    }
}

/// RAII guard for span context
pub struct LogGuard {
    _span: tracing::span::Entered<'static>,
    start: std::time::Instant,
    name: String,
}

impl LogGuard {
    fn new(span: tracing::Span, name: String) -> Self {
        let start = std::time::Instant::now();
        let static_span = Box::leak(Box::new(span));
        Self {
            _span: static_span.enter(),
            start,
            name,
        }
    }

    /// Returns the elapsed time since the span was entered
    #[must_use]
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}

impl Drop for LogGuard {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        #[allow(clippy::cast_possible_truncation)]
        let duration_ms = duration.as_millis() as u64;
        tracing::debug!(span = self.name.as_str(), duration_ms, "span completed");
    }
}

/// Builder for tracing spans
pub struct SpanBuilder {
    /// Name of the span
    name: String,
    /// Log level for the span
    level: LogLevel,
    /// Additional structured fields for the span
    fields: Vec<(String, String)>,
}

impl SpanBuilder {
    /// Creates a new span builder with the specified name
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            level: LogLevel::Debug,
            fields: Vec::new(),
        }
    }

    /// Sets the log level for the span
    #[must_use]
    pub const fn level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    /// Adds a structured field to the span
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn field(mut self, key: &str, value: impl ToString) -> Self {
        self.fields.push((key.to_string(), value.to_string()));
        self
    }

    /// Enters the span and returns a guard that will exit on drop
    pub fn enter(self) -> LogGuard {
        let span = match self.level {
            LogLevel::Trace => tracing::trace_span!("span", name = %self.name),
            LogLevel::Debug => tracing::debug_span!("span", name = %self.name),
            LogLevel::Info => tracing::info_span!("span", name = %self.name),
            LogLevel::Warn => tracing::warn_span!("span", name = %self.name),
            LogLevel::Error => tracing::error_span!("span", name = %self.name),
        };
        for (key, value) in &self.fields {
            span.record(key.as_str(), value.as_str());
        }
        LogGuard::new(span, self.name)
    }
}

/// Initialize global logging with the given configuration
///
/// # Errors
///
/// Returns an error if the logging subscriber fails to initialize or if file operations fail.
///
/// # Panics
///
/// May panic if file cloning fails during initialization.
pub fn init_logging(config: &LogConfig) -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(config.level.to_string()));

    match &config.output {
        LogOutput::Stdout => apply_fmt(config, std::io::stdout, filter)?,
        LogOutput::Stderr => apply_fmt(config, std::io::stderr, filter)?,
        LogOutput::File(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            apply_fmt(config, move || file.try_clone().unwrap(), filter)?;
        }
        LogOutput::Both { stdout, file } => {
            if let Some(parent) = file.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file_handle = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(file)?;
            if *stdout {
                let combined = CombinedWriter {
                    stdout: Arc::new(Mutex::new(std::io::stdout())),
                    file: Arc::new(Mutex::new(file_handle)),
                };
                apply_fmt(config, combined, filter)?;
            } else {
                apply_fmt(config, move || file_handle.try_clone().unwrap(), filter)?;
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct CombinedWriter {
    stdout: Arc<Mutex<std::io::Stdout>>,
    file: Arc<Mutex<std::fs::File>>,
}

impl Write for CombinedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stdout.lock().write_all(buf)?;
        self.file.lock().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stdout.lock().flush()?;
        self.file.lock().flush()?;
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CombinedWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn apply_fmt<W>(config: &LogConfig, writer: W, filter: EnvFilter) -> Result<()>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let init_result = match config.format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_writer(writer)
            .with_target(config.include_target)
            .with_file(config.include_file_line)
            .with_line_number(config.include_file_line)
            .with_thread_ids(config.include_thread_id)
            .with_env_filter(filter)
            .try_init(),
        LogFormat::Pretty => tracing_subscriber::fmt()
            .pretty()
            .with_writer(writer)
            .with_target(config.include_target)
            .with_file(config.include_file_line)
            .with_line_number(config.include_file_line)
            .with_thread_ids(config.include_thread_id)
            .with_env_filter(filter)
            .try_init(),
        LogFormat::Compact => tracing_subscriber::fmt()
            .compact()
            .with_writer(writer)
            .with_target(config.include_target)
            .with_file(config.include_file_line)
            .with_line_number(config.include_file_line)
            .with_thread_ids(config.include_thread_id)
            .with_env_filter(filter)
            .try_init(),
    };
    init_result.map_err(|e| TelemetryError::Init(format!("Failed to init subscriber: {e}")))
}

#[cfg(test)]
mod tests;
