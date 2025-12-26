//! warp CLI - GPU-accelerated bulk data transfer

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use warp_cli::{Cli, Commands, StreamAction, RetentionAction, LegalHoldAction, AliasAction};

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
        // ============= Transfer Commands =============
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

        // ============= S3-Compatible Storage Commands =============
        Commands::List { path, recursive, json } => {
            warp_cli::commands::storage::list(&path, recursive, json).await
        }
        Commands::MakeBucket { bucket, with_lock, with_versioning } => {
            warp_cli::commands::storage::make_bucket(&bucket, with_lock, with_versioning).await
        }
        Commands::RemoveBucket { bucket, force } => {
            warp_cli::commands::storage::remove_bucket(&bucket, force).await
        }
        Commands::Copy { source, destination, recursive, preserve } => {
            warp_cli::commands::storage::copy(&source, &destination, recursive, preserve).await
        }
        Commands::Move { source, destination, recursive } => {
            warp_cli::commands::storage::mv(&source, &destination, recursive).await
        }
        Commands::Remove { path, recursive, force, bypass_governance, versions } => {
            warp_cli::commands::storage::remove(&path, recursive, force, bypass_governance, versions).await
        }
        Commands::Cat { path, version_id } => {
            warp_cli::commands::storage::cat(&path, version_id.as_deref()).await
        }
        Commands::Stat { path, version_id } => {
            warp_cli::commands::storage::stat(&path, version_id.as_deref()).await
        }

        // ============= Retention Commands =============
        Commands::Retention { action } => {
            match action {
                RetentionAction::Set { path, mode, days, until, version_id } => {
                    warp_cli::commands::storage::retention_set(
                        &path, &mode, days, until.as_deref(), version_id.as_deref()
                    ).await
                }
                RetentionAction::Get { path, version_id } => {
                    warp_cli::commands::storage::retention_get(&path, version_id.as_deref()).await
                }
                RetentionAction::Clear { path, version_id, bypass_governance } => {
                    warp_cli::commands::storage::retention_clear(
                        &path, version_id.as_deref(), bypass_governance
                    ).await
                }
            }
        }

        // ============= Legal Hold Commands =============
        Commands::LegalHold { action } => {
            match action {
                LegalHoldAction::Set { path, version_id } => {
                    warp_cli::commands::storage::legal_hold_set(&path, version_id.as_deref()).await
                }
                LegalHoldAction::Clear { path, version_id } => {
                    warp_cli::commands::storage::legal_hold_clear(&path, version_id.as_deref()).await
                }
                LegalHoldAction::Get { path, version_id } => {
                    warp_cli::commands::storage::legal_hold_get(&path, version_id.as_deref()).await
                }
            }
        }

        // ============= Alias Commands =============
        Commands::Alias { action } => {
            match action {
                AliasAction::Set { alias, url, access_key, secret_key } => {
                    warp_cli::commands::storage::alias_set(
                        &alias, &url, access_key.as_deref(), secret_key.as_deref()
                    ).await
                }
                AliasAction::Remove { alias } => {
                    warp_cli::commands::storage::alias_remove(&alias).await
                }
                AliasAction::List => {
                    warp_cli::commands::storage::alias_list().await
                }
            }
        }
    }
}
