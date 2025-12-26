//! Transfer engine - orchestrates send/fetch operations

use crate::analyzer::{analyze_payload, CompressionHint, PayloadAnalysis};
use crate::session::{Session, SessionState};
use crate::{Error, Result};
use bytes::Bytes;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use warp_ec::{ErasureConfig, ErasureEncoder, ErasureDecoder};
use warp_format::{Compression, SparseMerkleTree, WarpReader, WarpWriter, WarpWriterConfig};
use warp_hash::Hasher;
use warp_net::codec::WireMerkleProof;
use warp_net::{Frame, WarpEndpoint};

/// Chunk verification mode during transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerificationMode {
    /// No per-chunk verification (default)
    #[default]
    None,
    /// Verify final Merkle root only
    Final,
    /// Verify each chunk with Merkle proof (O(log n) per chunk)
    PerChunk,
    /// Random sampling verification (verify N% of chunks)
    Sampling {
        /// Percentage of chunks to verify (1-100)
        percent: u8,
    },
}

/// Transfer engine configuration
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Maximum concurrent chunks
    pub max_concurrent_chunks: usize,
    /// Enable GPU acceleration
    pub enable_gpu: bool,
    /// Compression level (0-22 for zstd, 0-12 for lz4)
    pub compression_level: i32,
    /// Compression algorithm
    pub compression: Compression,
    /// Verify integrity on completion
    pub verify_on_complete: bool,
    /// Erasure coding configuration for fault-tolerant transfers
    ///
    /// When set, chunks are encoded with Reed-Solomon erasure coding
    /// before transmission, allowing recovery from shard loss.
    pub erasure_config: Option<ErasureConfig>,
    /// Chunk verification mode
    ///
    /// Controls how and when chunk integrity is verified during transfer.
    pub verification_mode: VerificationMode,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            max_concurrent_chunks: 16,
            enable_gpu: true,
            compression_level: 3,
            compression: Compression::Zstd,
            verify_on_complete: true,
            erasure_config: None,
            verification_mode: VerificationMode::None,
        }
    }
}

impl TransferConfig {
    /// Enable RS(10,4) erasure coding for fault-tolerant transfers
    ///
    /// This provides 40% redundancy, allowing recovery from up to 4 lost shards.
    pub fn with_erasure_coding(mut self) -> Self {
        self.erasure_config = Some(ErasureConfig::rs_10_4());
        self
    }

    /// Enable erasure coding with a custom configuration
    pub fn with_erasure_config(mut self, config: ErasureConfig) -> Self {
        self.erasure_config = Some(config);
        self
    }

    /// Enable per-chunk Merkle verification
    ///
    /// Each chunk is verified with an O(log n) proof during transfer.
    pub fn with_per_chunk_verification(mut self) -> Self {
        self.verification_mode = VerificationMode::PerChunk;
        self
    }

    /// Enable sampling verification (verify N% of chunks)
    pub fn with_sampling_verification(mut self, percent: u8) -> Self {
        self.verification_mode = VerificationMode::Sampling {
            percent: percent.min(100),
        };
        self
    }

    /// Set verification mode
    pub fn with_verification_mode(mut self, mode: VerificationMode) -> Self {
        self.verification_mode = mode;
        self
    }
}

/// Progress callback type
pub type ProgressCallback = Arc<dyn Fn(TransferProgress) + Send + Sync>;

/// Transfer progress information
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Total bytes
    pub total_bytes: u64,
    /// Chunks completed
    pub chunks_completed: u64,
    /// Total chunks
    pub total_chunks: u64,
    /// Current file being processed
    pub current_file: Option<String>,
    /// Transfer speed in bytes per second
    pub bytes_per_second: f64,
}

/// Main transfer engine
pub struct TransferEngine {
    config: TransferConfig,
    #[allow(dead_code)]
    semaphore: Arc<Semaphore>,
    progress_callback: Option<ProgressCallback>,
}

impl TransferEngine {
    /// Create a new transfer engine
    pub fn new(config: TransferConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_chunks));
        Self {
            config,
            semaphore,
            progress_callback: None,
        }
    }

    /// Set progress callback
    pub fn with_progress(mut self, callback: ProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// High-level send operation (auto-detect local vs remote)
    pub async fn send(&self, source: &Path, dest: &str) -> Result<Session> {
        let mut session = Session::new(source.to_path_buf(), dest.to_string());

        if is_remote(dest) {
            self.send_remote(source, dest, &mut session).await?;
        } else {
            let dest_path = Path::new(dest);
            self.send_local(source, dest_path, &mut session).await?;
        }

        Ok(session)
    }

    /// High-level fetch operation (auto-detect local vs remote)
    pub async fn fetch(&self, source: &str, dest: &Path) -> Result<Session> {
        let mut session = Session::new(PathBuf::from(source), source.to_string());

        if is_remote(source) {
            self.fetch_remote(source, dest, &mut session).await?;
        } else {
            let source_path = Path::new(source);
            self.fetch_local(source_path, dest, &mut session).await?;
        }

        Ok(session)
    }

    /// Send to local archive
    pub async fn send_local(
        &self,
        source: &Path,
        dest: &Path,
        session: &mut Session,
    ) -> Result<()> {
        session.set_state(SessionState::Analyzing);
        tracing::info!("Analyzing payload: {}", source.display());

        let analysis = analyze_payload(source).await?;
        tracing::info!(
            "Analysis: {} files, {} bytes, entropy: {:.2}",
            analysis.file_count,
            analysis.total_size,
            analysis.avg_entropy
        );

        session.total_bytes = analysis.total_size;

        let compression = select_compression(&analysis, &self.config);
        let config = WarpWriterConfig {
            compression,
            chunk_size: analysis.chunk_size_hint,
            min_chunk_size: analysis.chunk_size_hint / 4,
            max_chunk_size: analysis.chunk_size_hint * 4,
            ..Default::default()
        };

        session.set_state(SessionState::Transferring);
        tracing::info!("Creating archive: {}", dest.display());

        let start_time = Instant::now();
        let mut writer = WarpWriter::create_with_config(dest, config)?;

        if source.is_dir() {
            writer.add_directory(source, "")?;
        } else {
            let filename = source
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");
            writer.add_file(source, filename)?;
        }

        writer.finish()?;
        let elapsed = start_time.elapsed();

        let reader = WarpReader::open(dest)?;
        let header = reader.header();
        session.merkle_root = Some(header.merkle_root);
        session.total_chunks = header.total_chunks;
        session.transferred_bytes = header.compressed_size;

        tracing::info!(
            "Archive created: {} chunks, {:.2} MB compressed in {:.2}s",
            header.total_chunks,
            header.compressed_size as f64 / 1_048_576.0,
            elapsed.as_secs_f64()
        );

        if self.config.verify_on_complete {
            session.set_state(SessionState::Verifying);
            tracing::info!("Verifying archive integrity");

            let reader = WarpReader::open(dest)?;
            let verified = reader.verify()?;

            if !verified {
                session.set_error("Archive verification failed".to_string());
                return Err(Error::Session("Verification failed".to_string()));
            }

            tracing::info!("Archive verified successfully");
        }

        session.set_state(SessionState::Completed);
        Ok(())
    }

    /// Send to remote server
    pub async fn send_remote(
        &self,
        source: &Path,
        dest: &str,
        session: &mut Session,
    ) -> Result<()> {
        let (addr, remote_path) = parse_remote(dest)?;

        session.set_state(SessionState::Analyzing);
        let analysis = analyze_payload(source).await?;
        session.total_bytes = analysis.total_size;

        session.set_state(SessionState::Negotiating);
        tracing::info!("Connecting to {}", addr);

        let socket_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            Error::Session(format!("Invalid address: {}", e))
        })?;

        let endpoint = WarpEndpoint::client().await?;
        let conn = endpoint.connect(socket_addr, "warp-transfer").await?;

        let params = conn.handshake().await?;
        tracing::info!("Handshake complete, negotiated parameters: {:?}", params);

        let temp_archive = tempfile::NamedTempFile::new()?;
        let temp_path = temp_archive.path();

        tracing::info!("Creating temporary archive");
        let compression = select_compression(&analysis, &self.config);
        let config = WarpWriterConfig {
            compression,
            chunk_size: analysis.chunk_size_hint,
            ..Default::default()
        };

        let mut writer = WarpWriter::create_with_config(temp_path, config)?;
        if source.is_dir() {
            writer.add_directory(source, "")?;
        } else {
            let filename = source
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file");
            writer.add_file(source, filename)?;
        }

        writer.finish()?;

        let temp_reader = WarpReader::open(temp_path)?;
        let temp_header = temp_reader.header();
        session.merkle_root = Some(temp_header.merkle_root);
        session.total_chunks = temp_header.total_chunks;

        session.set_state(SessionState::Transferring);
        tracing::info!("Sending {} chunks", temp_header.total_chunks);

        let metadata = Bytes::from(create_metadata(&remote_path, &analysis));
        conn.send_frame(Frame::Plan {
            total_size: temp_header.compressed_size,
            num_chunks: temp_header.total_chunks as u32,
            chunk_size: analysis.chunk_size_hint,
            metadata,
        })
        .await?;

        let accept_frame = conn.recv_frame().await?;
        if !matches!(accept_frame, Frame::Accept) {
            session.set_error("Remote rejected transfer".to_string());
            return Err(Error::Network(warp_net::Error::Protocol(
                "Transfer rejected".to_string(),
            )));
        }

        let reader = WarpReader::open(temp_path)?;
        let start_time = Instant::now();

        // Create erasure encoder if configured
        let encoder = self.config.erasure_config.as_ref()
            .map(|ec| ErasureEncoder::new(ec.clone()));

        // Build Merkle tree for per-chunk verification if needed
        let merkle_tree: Option<SparseMerkleTree> = if matches!(self.config.verification_mode, VerificationMode::PerChunk | VerificationMode::Sampling { .. }) {
            // Collect all chunk hashes
            let chunk_hashes: Vec<[u8; 32]> = (0..temp_header.total_chunks as usize)
                .map(|i| {
                    let chunk = reader.read_chunk(i).unwrap_or_default();
                    let mut hasher = Hasher::new();
                    hasher.update(&chunk);
                    hasher.finalize()
                })
                .collect();
            Some(SparseMerkleTree::from_leaves(chunk_hashes))
        } else {
            None
        };

        // Determine which chunks to verify based on mode
        let should_verify_chunk = |idx: usize| -> bool {
            match self.config.verification_mode {
                VerificationMode::None | VerificationMode::Final => false,
                VerificationMode::PerChunk => true,
                VerificationMode::Sampling { percent } => {
                    // Simple deterministic sampling based on chunk index
                    (idx * 100 / temp_header.total_chunks.max(1) as usize) < percent as usize
                        || idx % (100 / percent.max(1) as usize) == 0
                }
            }
        };

        for chunk_idx in 0..temp_header.total_chunks as usize {
            if session.is_chunk_completed(chunk_idx as u64) {
                continue;
            }

            let chunk_data = reader.read_chunk(chunk_idx)?;
            let mut hasher = Hasher::new();
            hasher.update(&chunk_data);
            let chunk_hash = hasher.finalize();

            // Send with erasure coding or plain chunk
            if let Some(ref enc) = encoder {
                // Encode chunk into shards and send each
                let shards = enc.encode(&chunk_data)
                    .map_err(|e| Error::Session(format!("Erasure encoding failed: {}", e)))?;
                let total_shards = shards.len() as u16;

                for (shard_idx, shard_data) in shards.into_iter().enumerate() {
                    conn.send_frame(Frame::Shard {
                        chunk_id: chunk_idx as u32,
                        shard_idx: shard_idx as u16,
                        total_shards,
                        data: Bytes::from(shard_data),
                    })
                    .await?;
                }

                session.transferred_bytes += chunk_data.len() as u64;
            } else {
                // Send plain chunk
                let chunk_bytes = Bytes::from(chunk_data);
                conn.send_frame(Frame::Chunk {
                    chunk_id: chunk_idx as u32,
                    data: chunk_bytes.clone(),
                })
                .await?;

                session.transferred_bytes += chunk_bytes.len() as u64;
            }

            // Send per-chunk verification if enabled
            if should_verify_chunk(chunk_idx) {
                if let Some(ref tree) = merkle_tree {
                    let proof = tree.generate_proof(chunk_idx);

                    // Pack direction bits into bytes
                    let directions_packed: Vec<u8> = proof.directions
                        .chunks(8)
                        .map(|bits: &[bool]| {
                            bits.iter().enumerate().fold(0u8, |acc, (i, &b)| {
                                acc | ((b as u8) << i)
                            })
                        })
                        .collect();

                    // Convert to wire format
                    let wire_proof = WireMerkleProof {
                        siblings: proof.siblings,
                        leaf_index: proof.leaf_index as u32,
                        directions: directions_packed,
                    };

                    conn.send_frame(Frame::ChunkVerify {
                        chunk_id: chunk_idx as u32,
                        chunk_hash,
                        proof: wire_proof,
                    })
                    .await?;
                }
            }

            session.complete_chunk(chunk_idx as u64);

            if let Some(ref callback) = self.progress_callback {
                let elapsed = start_time.elapsed().as_secs_f64();
                let bps = if elapsed > 0.0 {
                    session.transferred_bytes as f64 / elapsed
                } else {
                    0.0
                };

                callback(TransferProgress {
                    bytes_transferred: session.transferred_bytes,
                    total_bytes: session.total_bytes,
                    chunks_completed: session.completed_chunks.len() as u64,
                    total_chunks: session.total_chunks,
                    current_file: None,
                    bytes_per_second: bps,
                });
            }
        }

        conn.send_frame(Frame::Done).await?;

        session.set_state(SessionState::Verifying);
        conn.send_frame(Frame::Verify {
            merkle_root: temp_header.merkle_root,
        })
        .await?;

        let verify_response = conn.recv_frame().await?;
        match verify_response {
            Frame::Ack { .. } => {
                tracing::info!("Remote verified archive successfully");
            }
            Frame::Error { message, .. } => {
                session.set_error(format!("Remote verification failed: {}", message));
                return Err(Error::Session("Remote verification failed".to_string()));
            }
            _ => {
                session.set_error("Unexpected response during verification".to_string());
                return Err(Error::Network(warp_net::Error::Protocol(
                    "Unexpected frame".to_string(),
                )));
            }
        }

        session.set_state(SessionState::Completed);
        tracing::info!("Transfer completed successfully");

        Ok(())
    }

    /// Fetch from local archive
    pub async fn fetch_local(
        &self,
        source: &Path,
        dest: &Path,
        session: &mut Session,
    ) -> Result<()> {
        session.set_state(SessionState::Analyzing);
        tracing::info!("Opening archive: {}", source.display());

        let reader = WarpReader::open(source)?;
        let (uncompressed, _compressed, _ratio) = reader.stats();

        session.total_bytes = uncompressed;
        session.total_chunks = reader.chunk_count() as u64;

        session.set_state(SessionState::Transferring);
        tracing::info!("Extracting to: {}", dest.display());

        let start_time = Instant::now();
        reader.extract_all(dest)?;
        let elapsed = start_time.elapsed();

        session.transferred_bytes = uncompressed;

        tracing::info!(
            "Extracted {} files ({:.2} MB) in {:.2}s",
            reader.file_count(),
            uncompressed as f64 / 1_048_576.0,
            elapsed.as_secs_f64()
        );

        if self.config.verify_on_complete {
            session.set_state(SessionState::Verifying);
            tracing::info!("Verifying extracted files");

            let verified = reader.verify()?;
            if !verified {
                session.set_error("Verification failed".to_string());
                return Err(Error::Session("Verification failed".to_string()));
            }

            tracing::info!("Files verified successfully");
        }

        session.set_state(SessionState::Completed);
        Ok(())
    }

    /// Fetch from remote server
    pub async fn fetch_remote(
        &self,
        source: &str,
        dest: &Path,
        session: &mut Session,
    ) -> Result<()> {
        let (addr, remote_path) = parse_remote(source)?;

        session.set_state(SessionState::Negotiating);
        tracing::info!("Connecting to {}", addr);

        let socket_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
            Error::Session(format!("Invalid address: {}", e))
        })?;

        let endpoint = WarpEndpoint::client().await?;
        let conn = endpoint.connect(socket_addr, "warp-transfer").await?;

        let _params = conn.handshake().await?;
        tracing::info!("Handshake complete");

        let _metadata = create_metadata(&remote_path, &PayloadAnalysis {
            total_size: 0,
            file_count: 0,
            avg_entropy: 0.0,
            compression_hint: CompressionHint::Unknown,
            chunk_size_hint: 4 * 1024 * 1024,
            file_types: std::collections::HashMap::new(),
        });

        conn.send_frame(Frame::Want {
            chunk_ids: vec![],
        })
        .await?;

        let plan_frame = conn.recv_frame().await?;
        let (total_size, num_chunks, chunk_size) = match plan_frame {
            Frame::Plan {
                total_size,
                num_chunks,
                chunk_size,
                ..
            } => (total_size, num_chunks, chunk_size),
            Frame::Error { message, .. } => {
                session.set_error(format!("Remote error: {}", message));
                return Err(Error::Network(warp_net::Error::Protocol(message)));
            }
            _ => {
                return Err(Error::Network(warp_net::Error::Protocol(
                    "Unexpected frame".to_string(),
                )));
            }
        };

        session.total_bytes = total_size;
        session.total_chunks = num_chunks as u64;

        conn.send_frame(Frame::Accept).await?;

        session.set_state(SessionState::Transferring);
        tracing::info!("Receiving {} chunks", num_chunks);

        let temp_archive = tempfile::NamedTempFile::new()?;
        let temp_path = temp_archive.path();

        let _writer = WarpWriter::create_with_config(
            temp_path,
            WarpWriterConfig {
                compression: Compression::None,
                chunk_size,
                ..Default::default()
            },
        )?;

        let start_time = Instant::now();
        let mut received_chunks = 0u32;

        loop {
            let frame = conn.recv_frame().await?;

            match frame {
                Frame::Chunk { chunk_id, data } => {
                    session.complete_chunk(chunk_id as u64);
                    session.transferred_bytes += data.len() as u64;
                    received_chunks += 1;

                    if let Some(ref callback) = self.progress_callback {
                        let elapsed = start_time.elapsed().as_secs_f64();
                        let bps = if elapsed > 0.0 {
                            session.transferred_bytes as f64 / elapsed
                        } else {
                            0.0
                        };

                        callback(TransferProgress {
                            bytes_transferred: session.transferred_bytes,
                            total_bytes: session.total_bytes,
                            chunks_completed: received_chunks as u64,
                            total_chunks: num_chunks as u64,
                            current_file: None,
                            bytes_per_second: bps,
                        });
                    }
                }
                Frame::Done => {
                    tracing::info!("Received all chunks");
                    break;
                }
                Frame::Error { message, .. } => {
                    session.set_error(format!("Transfer error: {}", message));
                    return Err(Error::Network(warp_net::Error::Protocol(message)));
                }
                _ => {
                    tracing::warn!("Unexpected frame during transfer");
                }
            }
        }

        session.set_state(SessionState::Verifying);

        let verify_frame = conn.recv_frame().await?;
        if let Frame::Verify { merkle_root } = verify_frame {
            session.merkle_root = Some(merkle_root);

            conn.send_frame(Frame::Ack {
                chunk_ids: (0..num_chunks).collect(),
            })
            .await?;
        }

        tracing::info!("Extracting received archive");
        let reader = WarpReader::open(temp_path)?;
        reader.extract_all(dest)?;

        session.set_state(SessionState::Completed);
        tracing::info!("Fetch completed successfully");

        Ok(())
    }

    /// Resume a paused session
    pub async fn resume(&self, session: &mut Session) -> Result<()> {
        if !session.can_resume() {
            return Err(Error::Session(
                "Session cannot be resumed".to_string(),
            ));
        }

        tracing::info!("Resuming session {}", session.id);

        let source = session.source.clone();
        let destination = session.destination.clone();

        if is_remote(&destination) {
            self.send_remote(&source, &destination, session)
                .await
        } else {
            let dest = Path::new(&destination);
            self.send_local(&source, dest, session).await
        }
    }
}

use std::path::PathBuf;

fn is_remote(dest: &str) -> bool {
    dest.contains(':') && !dest.starts_with('/') && !dest.starts_with('.')
}

fn parse_remote(dest: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = dest.splitn(2, '/').collect();

    let addr = parts[0].to_string();
    let path = if parts.len() > 1 {
        parts[1].to_string()
    } else {
        String::new()
    };

    Ok((addr, path))
}

fn select_compression(analysis: &PayloadAnalysis, config: &TransferConfig) -> Compression {
    match analysis.compression_hint {
        CompressionHint::AlreadyCompressed => Compression::None,
        CompressionHint::HighlyCompressible => config.compression,
        CompressionHint::Mixed => {
            if analysis.avg_entropy > 0.7 {
                Compression::Lz4
            } else {
                config.compression
            }
        }
        CompressionHint::Unknown => config.compression,
    }
}

fn create_metadata(path: &str, _analysis: &PayloadAnalysis) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Metadata {
        path: String,
    }

    let meta = Metadata {
        path: path.to_string(),
    };

    rmp_serde::to_vec(&meta).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_is_remote() {
        assert!(is_remote("localhost:8080"));
        assert!(is_remote("192.168.1.1:9000"));
        assert!(!is_remote("/local/path"));
        assert!(!is_remote("./relative/path"));
        assert!(!is_remote("file.txt"));
    }

    #[test]
    fn test_parse_remote() {
        let (addr, path) = parse_remote("localhost:8080/path/to/file").unwrap();
        assert_eq!(addr, "localhost:8080");
        assert_eq!(path, "path/to/file");

        let (addr, path) = parse_remote("192.168.1.1:9000").unwrap();
        assert_eq!(addr, "192.168.1.1:9000");
        assert_eq!(path, "");
    }

    #[tokio::test]
    async fn test_send_local() {
        let src_dir = tempdir().unwrap();
        let dest_dir = tempdir().unwrap();

        File::create(src_dir.path().join("test.txt"))
            .unwrap()
            .write_all(b"hello world")
            .unwrap();

        let dest_archive = dest_dir.path().join("test.warp");

        let engine = TransferEngine::new(TransferConfig::default());
        let mut session = Session::new(
            src_dir.path().to_path_buf(),
            dest_archive.display().to_string(),
        );

        engine
            .send_local(src_dir.path(), &dest_archive, &mut session)
            .await
            .unwrap();

        assert_eq!(session.state, SessionState::Completed);
        assert!(dest_archive.exists());
    }

    #[tokio::test]
    async fn test_fetch_local() {
        let src_dir = tempdir().unwrap();
        let archive_dir = tempdir().unwrap();
        let dest_dir = tempdir().unwrap();

        File::create(src_dir.path().join("test.txt"))
            .unwrap()
            .write_all(b"hello world")
            .unwrap();

        let archive_path = archive_dir.path().join("test.warp");
        let mut writer = WarpWriter::create(&archive_path).unwrap();
        writer.add_directory(src_dir.path(), "").unwrap();
        writer.finish().unwrap();

        let engine = TransferEngine::new(TransferConfig::default());
        let mut session = Session::new(
            archive_path.clone(),
            dest_dir.path().display().to_string(),
        );

        engine
            .fetch_local(&archive_path, dest_dir.path(), &mut session)
            .await
            .unwrap();

        assert_eq!(session.state, SessionState::Completed);
        assert!(dest_dir.path().join("test.txt").exists());
    }
}
