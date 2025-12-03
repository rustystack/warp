//! warp-cli library exports
//!
//! This library provides the core functionality for the warp CLI,
//! including shell completion generation.

pub mod completions;
pub mod commands;

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
