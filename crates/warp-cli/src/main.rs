//! warp CLI - GPU-accelerated bulk data transfer

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use warp_cli::{Cli, Commands, StreamAction};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Commands::Send { source, destination, compress, no_gpu, encrypt, password } => {
            warp_cli::commands::send::execute(&source, &destination, compress.as_deref(), no_gpu, encrypt, password.as_deref()).await
        }
        Commands::Fetch { source, destination, password } => {
            warp_cli::commands::fetch::execute(&source, &destination, password.as_deref()).await
        }
        Commands::Listen { port, bind } => {
            warp_cli::commands::listen::execute(&bind, port).await
        }
        Commands::Plan { source, destination } => {
            warp_cli::commands::plan::execute(&source, &destination).await
        }
        Commands::Probe { server } => {
            warp_cli::commands::probe::execute(&server).await
        }
        Commands::Info => {
            warp_cli::commands::info::execute().await
        }
        Commands::Resume { session } => {
            warp_cli::commands::resume::execute(&session).await
        }
        Commands::Bench { server, size } => {
            warp_cli::commands::bench::execute(&server, &size).await
        }
        Commands::Completions { shell, output } => {
            warp_cli::commands::completions::execute(shell, output.as_deref()).await
        }
        Commands::Stream { action } => {
            match action {
                StreamAction::Encrypt { password, chunk_size, no_gpu, progress } => {
                    warp_cli::commands::stream::encrypt(password.as_deref(), chunk_size, no_gpu, progress).await
                }
                StreamAction::Decrypt { password, no_gpu, progress } => {
                    warp_cli::commands::stream::decrypt(password.as_deref(), no_gpu, progress).await
                }
            }
        }
    }
}
