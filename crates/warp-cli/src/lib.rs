//! warp-cli library exports
//!
//! This library provides the core functionality for the warp CLI,
//! including shell completion generation.

#![allow(clippy::ptr_arg)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::unnecessary_unwrap)]

pub mod commands;
pub mod completions;

use clap::Parser;

#[derive(Parser)]
#[command(name = "warp")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand)]
pub enum Commands {
    /// Send files to a remote destination
    Send {
        /// Source path (local file or directory)
        source: String,
        /// Destination (e.g., server:/path or /local/path)
        destination: String,
        /// Compression algorithm override
        #[arg(long)]
        compress: Option<String>,
        /// Disable GPU acceleration
        #[arg(long)]
        no_gpu: bool,
        /// Encrypt the archive with a password
        #[arg(long)]
        encrypt: bool,
        /// Password for encryption (prompts if --encrypt is set but password not provided)
        #[arg(long)]
        password: Option<String>,
        /// Enable erasure coding for fault-tolerant transfers
        #[arg(long)]
        erasure: bool,
        /// Number of parity shards for erasure coding (default: 2)
        #[arg(long, default_value = "2")]
        parity_shards: u16,
        /// Number of data shards for erasure coding (default: 4)
        #[arg(long, default_value = "4")]
        data_shards: u16,
        /// Adaptive erasure coding - auto-adjust based on network conditions
        #[arg(long)]
        adaptive_erasure: bool,
        /// Number of parallel QUIC streams for shard transmission
        #[arg(long, default_value = "4")]
        parallel_streams: u16,
    },
    /// Fetch files from a remote source
    Fetch {
        /// Source (e.g., server:/path)
        source: String,
        /// Local destination path
        destination: String,
        /// Password for decryption (prompts if archive is encrypted)
        #[arg(long)]
        password: Option<String>,
    },
    /// Start a listener daemon
    Listen {
        /// Port to listen on
        #[arg(short, long, default_value = "9999")]
        port: u16,
        /// Bind address
        #[arg(short, long, default_value = "0.0.0.0")]
        bind: String,
    },
    /// Analyze and plan a transfer without executing
    Plan {
        /// Source path
        source: String,
        /// Destination
        destination: String,
    },
    /// Probe remote server capabilities
    Probe {
        /// Remote server address
        server: String,
    },
    /// Show local system capabilities
    Info,
    /// Resume an interrupted transfer
    Resume {
        /// Session ID to resume
        #[arg(long)]
        session: String,
    },
    /// Benchmark transfer to a remote server
    Bench {
        /// Remote server address
        server: String,
        /// Size of test data
        #[arg(long, default_value = "1G")]
        size: String,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
        /// Output directory (prints to stdout if not specified)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Real-time streaming encryption/decryption (pipe-based)
    Stream {
        #[command(subcommand)]
        action: StreamAction,
    },

    // ============= S3-Compatible Storage Commands =============
    /// List buckets or objects (mc ls)
    #[command(name = "ls")]
    List {
        /// Path (bucket or bucket/prefix)
        #[arg(default_value = "")]
        path: String,
        /// Recursive listing
        #[arg(short, long)]
        recursive: bool,
        /// JSON output
        #[arg(long)]
        json: bool,
    },

    /// Make a bucket (mc mb)
    #[command(name = "mb")]
    MakeBucket {
        /// Bucket name
        bucket: String,
        /// Enable Object Lock
        #[arg(long)]
        with_lock: bool,
        /// Enable versioning
        #[arg(long)]
        with_versioning: bool,
    },

    /// Remove a bucket (mc rb)
    #[command(name = "rb")]
    RemoveBucket {
        /// Bucket name
        bucket: String,
        /// Force removal of non-empty bucket
        #[arg(long)]
        force: bool,
    },

    /// Copy objects (mc cp)
    #[command(name = "cp")]
    Copy {
        /// Source path (local file or bucket/key)
        source: String,
        /// Destination path (local file or bucket/key)
        destination: String,
        /// Recursive copy
        #[arg(short, long)]
        recursive: bool,
        /// Preserve attributes
        #[arg(short = 'a', long)]
        preserve: bool,
    },

    /// Move objects (mc mv)
    #[command(name = "mv")]
    Move {
        /// Source path
        source: String,
        /// Destination path
        destination: String,
        /// Recursive move
        #[arg(short, long)]
        recursive: bool,
    },

    /// Remove objects (mc rm)
    #[command(name = "rm")]
    Remove {
        /// Path to remove (bucket/key)
        path: String,
        /// Recursive removal
        #[arg(short, long)]
        recursive: bool,
        /// Force removal (no confirmation)
        #[arg(long)]
        force: bool,
        /// Bypass governance retention
        #[arg(long)]
        bypass_governance: bool,
        /// Remove all versions
        #[arg(long)]
        versions: bool,
    },

    /// Display object contents (mc cat)
    #[command(name = "cat")]
    Cat {
        /// Object path (bucket/key)
        path: String,
        /// Specific version ID
        #[arg(long)]
        version_id: Option<String>,
    },

    /// Get object info/head (mc stat)
    #[command(name = "stat")]
    Stat {
        /// Object path (bucket/key)
        path: String,
        /// Specific version ID
        #[arg(long)]
        version_id: Option<String>,
    },

    /// Object retention management
    Retention {
        #[command(subcommand)]
        action: RetentionAction,
    },

    /// Legal hold management
    LegalHold {
        #[command(subcommand)]
        action: LegalHoldAction,
    },

    /// Set an alias for a storage endpoint
    Alias {
        #[command(subcommand)]
        action: AliasAction,
    },
}

/// Stream subcommands for pipe-based encryption/decryption
#[derive(clap::Subcommand)]
pub enum StreamAction {
    /// Encrypt data from stdin to stdout
    Encrypt {
        /// Encryption password (prompts if not provided)
        #[arg(long)]
        password: Option<String>,
        /// Chunk size in bytes (default: 64KB for low latency)
        #[arg(long, default_value = "65536")]
        chunk_size: usize,
        /// Disable GPU acceleration
        #[arg(long)]
        no_gpu: bool,
        /// Show progress to stderr
        #[arg(long)]
        progress: bool,
    },
    /// Decrypt data from stdin to stdout
    Decrypt {
        /// Decryption password (prompts if not provided)
        #[arg(long)]
        password: Option<String>,
        /// Disable GPU acceleration
        #[arg(long)]
        no_gpu: bool,
        /// Show progress to stderr
        #[arg(long)]
        progress: bool,
    },
}

/// Retention subcommands
#[derive(clap::Subcommand)]
pub enum RetentionAction {
    /// Set retention on an object
    Set {
        /// Object path (bucket/key)
        path: String,
        /// Retention mode (GOVERNANCE or COMPLIANCE)
        #[arg(long)]
        mode: String,
        /// Retention period in days
        #[arg(long)]
        days: Option<u32>,
        /// Retain until date (ISO 8601)
        #[arg(long)]
        until: Option<String>,
        /// Version ID
        #[arg(long)]
        version_id: Option<String>,
    },
    /// Get retention info for an object
    Get {
        /// Object path (bucket/key)
        path: String,
        /// Version ID
        #[arg(long)]
        version_id: Option<String>,
    },
    /// Clear retention (governance mode only)
    Clear {
        /// Object path (bucket/key)
        path: String,
        /// Version ID
        #[arg(long)]
        version_id: Option<String>,
        /// Bypass governance retention
        #[arg(long)]
        bypass_governance: bool,
    },
}

/// Legal hold subcommands
#[derive(clap::Subcommand)]
pub enum LegalHoldAction {
    /// Enable legal hold on an object
    Set {
        /// Object path (bucket/key)
        path: String,
        /// Version ID
        #[arg(long)]
        version_id: Option<String>,
    },
    /// Disable legal hold on an object
    Clear {
        /// Object path (bucket/key)
        path: String,
        /// Version ID
        #[arg(long)]
        version_id: Option<String>,
    },
    /// Get legal hold status
    Get {
        /// Object path (bucket/key)
        path: String,
        /// Version ID
        #[arg(long)]
        version_id: Option<String>,
    },
}

/// Alias management subcommands
#[derive(clap::Subcommand)]
pub enum AliasAction {
    /// Set or update an alias
    Set {
        /// Alias name
        alias: String,
        /// Endpoint URL
        url: String,
        /// Access key
        #[arg(long)]
        access_key: Option<String>,
        /// Secret key
        #[arg(long)]
        secret_key: Option<String>,
    },
    /// Remove an alias
    Remove {
        /// Alias name
        alias: String,
    },
    /// List all aliases
    List,
}
