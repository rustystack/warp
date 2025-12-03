//! Stream command - pipe-based real-time encryption/decryption
//!
//! This module provides CLI commands for streaming encryption/decryption
//! using stdin/stdout, ideal for piping data between tools.
//!
//! # Example Usage
//!
//! ```bash
//! # Encrypt a file to stdout
//! cat large_file.bin | warp stream encrypt --password secret > encrypted.bin
//!
//! # Decrypt and pipe to another tool
//! cat encrypted.bin | warp stream decrypt --password secret | tar xvf -
//!
//! # Chain with compression
//! tar cvf - /data | warp stream encrypt --password secret > backup.enc
//! ```

use anyhow::Result;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write as StdWrite};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use warp_crypto::kdf::derive_key;
use warp_stream::{PipelineBuilder, StreamConfig};

/// Header magic for identifying encrypted streams
const STREAM_MAGIC: &[u8; 8] = b"WARPSTRM";

/// Stream format version
const STREAM_VERSION: u8 = 1;

/// Header size: magic (8) + version (1) + salt (16) + nonce (12) = 37 bytes
const HEADER_SIZE: usize = 37;

/// A writer that collects data and tracks bytes written
struct CollectingWriter {
    data: Arc<Mutex<Vec<u8>>>,
}

impl CollectingWriter {
    fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
        let data = Arc::new(Mutex::new(Vec::new()));
        (Self { data: Arc::clone(&data) }, data)
    }
}

impl tokio::io::AsyncWrite for CollectingWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // Use try_lock since we're in poll context
        if let Ok(mut data) = self.data.try_lock() {
            data.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        } else {
            std::task::Poll::Pending
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// Encrypt data from stdin to stdout
pub async fn encrypt(
    password: Option<&str>,
    chunk_size: usize,
    no_gpu: bool,
    show_progress: bool,
) -> Result<()> {
    // Get password (prompt if not provided)
    let password = match password {
        Some(p) => p.to_string(),
        None => prompt_password("Encryption password: ")?,
    };

    // Derive encryption key from password
    let salt = rand::random::<[u8; 16]>();
    let key = derive_key_from_password(&password, &salt);
    let nonce: [u8; 12] = rand::random();

    // Configure the pipeline
    let config = StreamConfig::new()
        .with_chunk_size(chunk_size)
        .with_gpu(!no_gpu);

    let pipeline = PipelineBuilder::new()
        .with_config(config)
        .with_key(key)
        .with_nonce(nonce)
        .build()?;

    // Setup progress reporting if requested
    let progress = if show_progress {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let start_time = Instant::now();

    // Read all input first
    let mut stdin = tokio::io::stdin();
    let mut input_data = Vec::new();
    stdin.read_to_end(&mut input_data).await?;
    let input_size = input_data.len();

    // Create collecting writer for output
    let (writer, output_data) = CollectingWriter::new();

    // Run the encryption pipeline
    let input = std::io::Cursor::new(input_data);
    let stats = pipeline.run(input, writer).await?;

    // Get the encrypted data
    let encrypted = output_data.lock().await;
    let encrypted_len = encrypted.len();

    // Write header + encrypted data to stdout
    let mut stdout = tokio::io::stdout();
    stdout.write_all(STREAM_MAGIC).await?;
    stdout.write_all(&[STREAM_VERSION]).await?;
    stdout.write_all(&salt).await?;
    stdout.write_all(&nonce).await?;
    stdout.write_all(&encrypted).await?;
    stdout.flush().await?;

    let elapsed = start_time.elapsed();

    // Report progress
    if let Some(pb) = progress {
        let throughput_mbps = (input_size as f64 / 1_000_000.0) / elapsed.as_secs_f64();
        pb.finish_with_message(format!(
            "Encrypted {} bytes in {:.2}s ({:.2} MB/s)",
            input_size,
            elapsed.as_secs_f64(),
            throughput_mbps
        ));
    }

    // Print stats to stderr
    eprintln!(
        "{} {} bytes encrypted ({} output) | throughput: {:.2} GB/s | latency: {:.2}ms/chunk",
        style("✓").green(),
        input_size,
        encrypted_len + HEADER_SIZE,
        stats.throughput_gbps,
        stats.process_avg_latency.as_secs_f64() * 1000.0
    );

    Ok(())
}

/// Decrypt data from stdin to stdout
pub async fn decrypt(
    password: Option<&str>,
    no_gpu: bool,
    show_progress: bool,
) -> Result<()> {
    // Get password (prompt if not provided)
    let password = match password {
        Some(p) => p.to_string(),
        None => prompt_password("Decryption password: ")?,
    };

    // Setup progress reporting if requested
    let progress = if show_progress {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap(),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let start_time = Instant::now();

    // Read header from stdin
    let mut stdin = tokio::io::stdin();

    let mut magic = [0u8; 8];
    stdin.read_exact(&mut magic).await?;
    if &magic != STREAM_MAGIC {
        anyhow::bail!("Invalid stream header: not a warp encrypted stream");
    }

    let mut version = [0u8; 1];
    stdin.read_exact(&mut version).await?;
    if version[0] != STREAM_VERSION {
        anyhow::bail!(
            "Unsupported stream version: {} (expected {})",
            version[0],
            STREAM_VERSION
        );
    }

    let mut salt = [0u8; 16];
    stdin.read_exact(&mut salt).await?;

    let mut nonce = [0u8; 12];
    stdin.read_exact(&mut nonce).await?;

    // Derive key from password and salt
    let key = derive_key_from_password(&password, &salt);

    // Read remaining encrypted data
    let mut encrypted_data = Vec::new();
    stdin.read_to_end(&mut encrypted_data).await?;
    let encrypted_size = encrypted_data.len();

    // Configure the pipeline for decryption
    let config = StreamConfig::new()
        .with_gpu(!no_gpu);

    let pipeline = PipelineBuilder::new()
        .with_config(config)
        .with_key(key)
        .with_nonce(nonce)
        .build()?;

    // Create collecting writer for output
    let (writer, output_data) = CollectingWriter::new();

    // Run the decryption pipeline
    let input = std::io::Cursor::new(encrypted_data);
    let stats = pipeline.run(input, writer).await?;

    // Get the decrypted data
    let decrypted = output_data.lock().await;
    let decrypted_len = decrypted.len();

    // Write decrypted data to stdout
    let mut stdout = tokio::io::stdout();
    stdout.write_all(&decrypted).await?;
    stdout.flush().await?;

    let elapsed = start_time.elapsed();

    // Report progress
    if let Some(pb) = progress {
        let throughput_mbps = (encrypted_size as f64 / 1_000_000.0) / elapsed.as_secs_f64();
        pb.finish_with_message(format!(
            "Decrypted {} bytes in {:.2}s ({:.2} MB/s)",
            decrypted_len,
            elapsed.as_secs_f64(),
            throughput_mbps
        ));
    }

    // Print stats to stderr
    eprintln!(
        "{} {} bytes decrypted (from {} encrypted) | throughput: {:.2} GB/s | latency: {:.2}ms/chunk",
        style("✓").green(),
        decrypted_len,
        encrypted_size + HEADER_SIZE,
        stats.throughput_gbps,
        stats.process_avg_latency.as_secs_f64() * 1000.0
    );

    Ok(())
}

/// Prompt for password with hidden input
fn prompt_password(prompt: &str) -> Result<String> {
    eprint!("{}", prompt);
    io::stderr().flush()?;

    let password = rpassword::read_password()?;
    if password.is_empty() {
        anyhow::bail!("Password cannot be empty");
    }

    Ok(password)
}

/// Derive a 256-bit key from password using Argon2id
fn derive_key_from_password(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    *derive_key(password.as_bytes(), salt)
        .expect("Key derivation should succeed")
        .as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [0u8; 16];
        let key1 = derive_key_from_password("test", &salt);
        let key2 = derive_key_from_password("test", &salt);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salt() {
        let salt1 = [0u8; 16];
        let salt2 = [1u8; 16];
        let key1 = derive_key_from_password("test", &salt1);
        let key2 = derive_key_from_password("test", &salt2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_password() {
        let salt = [0u8; 16];
        let key1 = derive_key_from_password("test1", &salt);
        let key2 = derive_key_from_password("test2", &salt);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_stream_magic() {
        assert_eq!(STREAM_MAGIC.len(), 8);
        assert_eq!(STREAM_MAGIC, b"WARPSTRM");
    }

    #[test]
    fn test_header_size() {
        assert_eq!(HEADER_SIZE, 8 + 1 + 16 + 12);
    }
}
