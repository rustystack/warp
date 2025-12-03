//! send command implementation - creates .warp archives or sends to remote

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use warp_crypto::kdf::{derive_key, generate_salt};
use warp_format::merkle::MerkleTree;
use warp_format::{Compression, EncryptionKey, WarpReader, WarpWriter, WarpWriterConfig};
use warp_net::{Frame, WarpEndpoint};

/// Metadata for file transfer
#[derive(Debug, Clone, serde::Serialize)]
struct FileMetadata {
    /// File name
    name: String,
    /// Total original size
    total_size: u64,
    /// Is this a directory transfer
    is_directory: bool,
}

/// Execute the send command
///
/// Creates a .warp archive from the source path. If the destination ends with .warp
/// or is a local path (doesn't contain ":"), creates a local archive. Otherwise,
/// sends to remote server.
pub async fn execute(
    source: &str,
    destination: &str,
    compress: Option<&str>,
    _no_gpu: bool, // GPU not yet implemented
    encrypt: bool,
    password: Option<&str>,
) -> Result<()> {
    tracing::info!(
        source = source,
        destination = destination,
        compress = compress,
        encrypt = encrypt,
        "Starting send"
    );

    // Get encryption key if encryption is enabled
    let encryption_key = if encrypt {
        let password = get_password(password)?;
        let salt = generate_salt();
        let derived = derive_key(password.as_bytes(), &salt)
            .context("Failed to derive encryption key")?;
        Some(EncryptionKey::from_bytes(*derived.as_bytes()))
    } else {
        None
    };

    // Determine if this is a local archive creation or remote transfer
    if is_remote_dest(destination) {
        // Remote transfer
        let (host, port, remote_path) = parse_remote_dest(destination)?;
        send_remote(source, &host, port, &remote_path, compress, encryption_key).await
    } else {
        // Local archive creation
        create_local_archive(source, destination, compress, encryption_key).await
    }
}

/// Get password from argument or prompt user
fn get_password(password: Option<&str>) -> Result<String> {
    if let Some(p) = password {
        Ok(p.to_string())
    } else {
        // Prompt for password
        print!("Enter encryption password: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let password = input.trim().to_string();

        // Confirm password
        print!("Confirm password: ");
        io::stdout().flush()?;
        input.clear();
        io::stdin().read_line(&mut input)?;
        let confirm = input.trim();

        if password != confirm {
            anyhow::bail!("Passwords do not match");
        }

        if password.is_empty() {
            anyhow::bail!("Password cannot be empty");
        }

        Ok(password)
    }
}

/// Check if destination is remote (contains host:port)
fn is_remote_dest(dest: &str) -> bool {
    // Remote format: "host:port" or "host:port/path"
    // Local format: "/path/to/file.warp" or "file.warp"
    if dest.starts_with('/') || dest.starts_with('.') {
        return false;
    }
    if dest.ends_with(".warp") {
        return false;
    }
    dest.contains(':')
}

/// Parse remote destination into (host, port, path)
fn parse_remote_dest(dest: &str) -> Result<(String, u16, String)> {
    // Format: "host:port/path" or "host:port"
    // Example: "192.168.1.1:9999/backup" -> ("192.168.1.1", 9999, "/backup")

    let parts: Vec<&str> = dest.splitn(2, '/').collect();
    let host_port = parts[0];
    let remote_path = if parts.len() > 1 {
        format!("/{}", parts[1])
    } else {
        String::from("")
    };

    // Parse host:port
    let host_port_parts: Vec<&str> = host_port.splitn(2, ':').collect();
    if host_port_parts.len() != 2 {
        anyhow::bail!("Invalid remote destination format. Expected 'host:port' or 'host:port/path'");
    }

    let host = host_port_parts[0].to_string();
    let port: u16 = host_port_parts[1]
        .parse()
        .context("Invalid port number")?;

    Ok((host, port, remote_path))
}

/// Send to remote server
async fn send_remote(
    source: &str,
    host: &str,
    port: u16,
    remote_path: &str,
    compress: Option<&str>,
    encryption_key: Option<EncryptionKey>,
) -> Result<()> {
    let start_time = Instant::now();

    println!("Sending to {}:{}", host, port);
    if !remote_path.is_empty() {
        println!("Remote path: {}", remote_path);
    }
    println!();

    // Parse source path
    let source_path = PathBuf::from(source);
    if !source_path.exists() {
        anyhow::bail!("Source path does not exist: {}", source);
    }

    // Parse compression option
    let compression = match compress {
        None | Some("zstd") => Compression::Zstd,
        Some("lz4") => Compression::Lz4,
        Some("none") => Compression::None,
        Some(other) => {
            anyhow::bail!(
                "Unknown compression algorithm: {}. Use 'zstd', 'lz4', or 'none'.",
                other
            );
        }
    };

    println!("Compression: {:?}", compression);
    if encryption_key.is_some() {
        println!("Encryption: enabled");
    }

    // Create temporary archive
    let temp_dir = std::env::temp_dir();
    let temp_archive_path = temp_dir.join(format!("warp_send_{}.warp", std::process::id()));

    // Show analysis spinner
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    spinner.set_message("Analyzing source...");

    // Create archive configuration
    let mut config = match compression {
        Compression::Zstd => WarpWriterConfig::with_zstd(),
        Compression::Lz4 => WarpWriterConfig::with_lz4(),
        Compression::None => WarpWriterConfig::no_compression(),
    };

    // Add encryption if key provided
    if let Some(key) = encryption_key {
        config = config.with_encryption(key);
    }

    // Create the archive
    let mut writer = WarpWriter::create_with_config(&temp_archive_path, config)
        .context("Failed to create temporary archive")?;

    spinner.set_message("Adding files to archive...");

    // Determine if source is a file or directory
    let metadata = std::fs::metadata(&source_path)?;
    let is_directory = metadata.is_dir();
    let source_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("transfer")
        .to_string();

    if metadata.is_file() {
        // Single file - add with its name
        writer
            .add_file(&source_path, &source_name)
            .context("Failed to add file to archive")?;
    } else if metadata.is_dir() {
        // Directory - add recursively
        let dir_name = &source_name;
        writer
            .add_directory(&source_path, dir_name)
            .context("Failed to add directory to archive")?;
    } else {
        anyhow::bail!("Source is neither a file nor a directory");
    }

    spinner.set_message("Finalizing archive...");

    // Finish the archive
    writer.finish().context("Failed to finalize archive")?;

    spinner.finish_and_clear();

    // Get archive statistics
    let archive_metadata = std::fs::metadata(&temp_archive_path)?;
    let archive_size = archive_metadata.len();

    println!("Archive size: {}", format_bytes(archive_size));
    println!();

    // Open the archive for reading to get details
    let reader = WarpReader::open(&temp_archive_path).context("Failed to open archive")?;
    let file_count = reader.file_count();
    let (original_size, compressed_size, _ratio) = reader.stats();

    // Read entire archive into memory for transfer
    spinner.set_message("Loading archive for transfer...");
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

    let mut archive_data = Vec::with_capacity(archive_size as usize);
    let mut archive_file = File::open(&temp_archive_path).await?;
    archive_file.read_to_end(&mut archive_data).await?;

    spinner.finish_and_clear();

    // Calculate chunks
    const CHUNK_SIZE: usize = 1024 * 1024; // 1MB chunks
    let num_chunks = (archive_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;

    println!("Files: {}", file_count);
    println!("Total size: {}", format_bytes(original_size));
    println!("Transfer chunks: {}", num_chunks);
    println!();

    // Connect to remote server
    println!("Connecting to {}:{}...", host, port);

    let addr = format!("{}:{}", host, port)
        .parse()
        .context("Invalid remote address")?;

    let endpoint = WarpEndpoint::client()
        .await
        .context("Failed to create client endpoint")?;

    let conn = endpoint
        .connect(addr, "warp-server")
        .await
        .context("Failed to connect to server")?;

    println!("Connected, performing handshake...");

    // Perform handshake
    let params = conn.handshake().await.context("Handshake failed")?;

    tracing::debug!(
        compression = params.compression,
        chunk_size = params.chunk_size,
        streams = params.parallel_streams,
        "Handshake complete"
    );

    println!("Handshake complete");
    println!();

    // Create metadata
    let file_metadata = FileMetadata {
        name: source_name.clone(),
        total_size: original_size,
        is_directory,
    };

    let metadata_bytes =
        rmp_serde::to_vec(&file_metadata).context("Failed to encode metadata")?;

    // Send PLAN frame
    conn.send_frame(Frame::Plan {
        total_size: archive_data.len() as u64,
        num_chunks: num_chunks as u32,
        chunk_size: CHUNK_SIZE as u32,
        metadata: metadata_bytes,
    })
    .await
    .context("Failed to send PLAN")?;

    // Wait for ACCEPT
    let frame = conn.recv_frame().await.context("Failed to receive ACCEPT")?;
    match frame {
        Frame::Accept => {}
        Frame::Error { code, message } => {
            anyhow::bail!("Server rejected transfer: {} - {}", code, message);
        }
        _ => {
            anyhow::bail!("Expected ACCEPT frame");
        }
    }

    println!("Server accepted transfer, sending chunks...");

    // Setup progress bar
    let progress = ProgressBar::new(archive_data.len() as u64);
    progress.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
        .unwrap()
        .progress_chars("#>-"),
    );

    // Collect chunk hashes for Merkle tree verification
    let mut chunk_hashes: Vec<[u8; 32]> = Vec::with_capacity(num_chunks);

    // Send chunks
    for chunk_id in 0..num_chunks {
        let start = chunk_id * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, archive_data.len());
        let chunk_data = &archive_data[start..end];

        // Hash chunk for Merkle tree
        chunk_hashes.push(warp_hash::hash(chunk_data));

        conn.send_chunk(chunk_id as u32, chunk_data)
            .await
            .context("Failed to send chunk")?;

        progress.set_position(end as u64);

        // Wait for ACK
        let frame = conn.recv_frame().await.context("Failed to receive ACK")?;
        match frame {
            Frame::Ack { chunk_ids } => {
                if !chunk_ids.contains(&(chunk_id as u32)) {
                    anyhow::bail!("Unexpected ACK for chunk {}", chunk_id);
                }
            }
            Frame::Nack { chunk_ids, reason } => {
                if chunk_ids.contains(&(chunk_id as u32)) {
                    anyhow::bail!("Server rejected chunk {}: {}", chunk_id, reason);
                }
            }
            Frame::Error { code, message } => {
                anyhow::bail!("Server error: {} - {}", code, message);
            }
            _ => {
                anyhow::bail!("Expected ACK frame");
            }
        }
    }

    progress.finish_with_message("All chunks sent");

    // Send DONE frame
    conn.send_frame(Frame::Done)
        .await
        .context("Failed to send DONE")?;

    // Build Merkle tree from chunk hashes and get root
    let merkle_tree = MerkleTree::from_leaves(chunk_hashes);
    let merkle_root = merkle_tree.root();

    // Send VERIFY frame with merkle root
    conn.send_frame(Frame::Verify { merkle_root })
        .await
        .context("Failed to send VERIFY")?;

    // Wait for final acknowledgment
    let frame = conn
        .recv_frame()
        .await
        .context("Failed to receive final ACK")?;
    match frame {
        Frame::Accept => {}
        Frame::Error { code, message } => {
            anyhow::bail!("Server verification failed: {} - {}", code, message);
        }
        _ => {
            anyhow::bail!("Expected final ACCEPT frame");
        }
    }

    let duration = start_time.elapsed();

    // Print summary
    println!();
    println!("Transfer completed successfully");
    println!();
    println!("Files transferred: {}", file_count);
    println!("Total size: {}", format_bytes(original_size));
    println!("Compressed size: {}", format_bytes(compressed_size));
    println!("Transfer size: {}", format_bytes(archive_data.len() as u64));
    println!("Duration: {:.2}s", duration.as_secs_f64());

    if archive_data.len() > 0 {
        let throughput = archive_data.len() as f64 / duration.as_secs_f64();
        println!("Throughput: {}/s", format_bytes(throughput as u64));
    }

    // Cleanup temporary archive
    tokio::fs::remove_file(&temp_archive_path).await.ok();

    // Close connection
    conn.close().await.ok();

    Ok(())
}

/// Create a local .warp archive
async fn create_local_archive(
    source: &str,
    destination: &str,
    compress: Option<&str>,
    encryption_key: Option<EncryptionKey>,
) -> Result<()> {
    let start_time = Instant::now();

    // Parse source path
    let source_path = PathBuf::from(source);
    if !source_path.exists() {
        anyhow::bail!("Source path does not exist: {}", source);
    }

    // Parse destination path
    let dest_path = PathBuf::from(destination);

    // Ensure destination ends with .warp
    let archive_path = if dest_path.extension().and_then(|s| s.to_str()) == Some("warp") {
        dest_path
    } else {
        dest_path.with_extension("warp")
    };

    // Create parent directory if it doesn't exist
    if let Some(parent) = archive_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .context("Failed to create destination directory")?;
        }
    }

    // Parse compression option
    let compression = match compress {
        None | Some("zstd") => Compression::Zstd,
        Some("lz4") => Compression::Lz4,
        Some("none") => Compression::None,
        Some(other) => {
            anyhow::bail!(
                "Unknown compression algorithm: {}. Use 'zstd', 'lz4', or 'none'.",
                other
            );
        }
    };

    // Create writer configuration
    let mut config = match compression {
        Compression::Zstd => WarpWriterConfig::with_zstd(),
        Compression::Lz4 => WarpWriterConfig::with_lz4(),
        Compression::None => WarpWriterConfig::no_compression(),
    };

    // Add encryption if key provided
    if let Some(key) = encryption_key.clone() {
        config = config.with_encryption(key);
    }

    println!("Creating archive: {}", archive_path.display());
    println!("Compression: {:?}", compression);
    if encryption_key.is_some() {
        println!("Encryption: enabled");
    }
    println!();

    // Show analysis spinner
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")
            .unwrap()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(100));
    spinner.set_message("Analyzing source...");

    // Create the archive
    let mut writer = WarpWriter::create_with_config(&archive_path, config)
        .context("Failed to create archive")?;

    spinner.set_message("Adding files...");

    // Determine if source is a file or directory
    let metadata = std::fs::metadata(&source_path)?;
    if metadata.is_file() {
        // Single file - add with its name
        let file_name = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");
        writer
            .add_file(&source_path, file_name)
            .context("Failed to add file to archive")?;
    } else if metadata.is_dir() {
        // Directory - add recursively
        let dir_name = source_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        writer
            .add_directory(&source_path, dir_name)
            .context("Failed to add directory to archive")?;
    } else {
        anyhow::bail!("Source is neither a file nor a directory");
    }

    spinner.set_message("Finalizing archive...");

    // Finish the archive
    writer.finish().context("Failed to finalize archive")?;

    spinner.finish_and_clear();

    // Get archive statistics
    let archive_metadata = std::fs::metadata(&archive_path)?;
    let archive_size = archive_metadata.len();

    let duration = start_time.elapsed();

    // Print summary
    println!("Archive created successfully");
    println!();
    println!("Archive: {}", archive_path.display());
    println!("Size: {}", format_bytes(archive_size));
    println!("Duration: {:.2}s", duration.as_secs_f64());

    if archive_size > 0 {
        let throughput = archive_size as f64 / duration.as_secs_f64();
        println!("Throughput: {}/s", format_bytes(throughput as u64));
    }

    Ok(())
}

/// Format bytes into human-readable string
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_is_remote_dest() {
        assert!(is_remote_dest("192.168.1.1:9999"));
        assert!(is_remote_dest("192.168.1.1:9999/backup"));
        assert!(is_remote_dest("localhost:8080"));
        assert!(!is_remote_dest("/tmp/test.warp"));
        assert!(!is_remote_dest("./test.warp"));
        assert!(!is_remote_dest("test.warp"));
        assert!(!is_remote_dest("/var/data"));
    }

    #[test]
    fn test_parse_remote_dest() {
        let (host, port, path) = parse_remote_dest("192.168.1.1:9999").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 9999);
        assert_eq!(path, "");

        let (host, port, path) = parse_remote_dest("192.168.1.1:9999/backup").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 9999);
        assert_eq!(path, "/backup");

        let (host, port, path) = parse_remote_dest("localhost:8080/test/path").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/test/path");

        assert!(parse_remote_dest("invalid").is_err());
        assert!(parse_remote_dest("localhost").is_err());
    }
}
