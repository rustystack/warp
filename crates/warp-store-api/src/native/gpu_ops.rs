//! GPU-accelerated operations endpoints
//!
//! High-performance GPU endpoints for:
//! - BLAKE3 hashing (15-20 GB/s on RTX 4090)
//! - ChaCha20-Poly1305 encryption (20+ GB/s)
//! - GPU capabilities and memory info
//!
//! These endpoints require the `gpu` feature to be enabled.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use warp_store::ObjectKey;
use warp_store::backend::StorageBackend;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

// =============================================================================
// GPU Hash Operations
// =============================================================================

/// Request for GPU-accelerated hashing
#[derive(Debug, Deserialize)]
pub struct GpuHashRequest {
    /// Bucket name
    pub bucket: String,
    /// Object key
    pub key: String,
    /// Hash algorithm (currently only "blake3" supported)
    #[serde(default = "default_blake3")]
    pub algorithm: String,
}

fn default_blake3() -> String {
    "blake3".to_string()
}

/// Response from GPU hash operation
#[derive(Debug, Serialize)]
pub struct GpuHashResponse {
    /// Hash result (hex-encoded)
    pub hash: String,
    /// Time taken in milliseconds
    pub time_ms: u64,
    /// Throughput in GB/s
    pub throughput_gbps: f64,
    /// Whether GPU was used (vs CPU fallback)
    pub gpu_used: bool,
    /// Object size in bytes
    pub object_size: u64,
}

/// GPU-accelerated hash of an object
///
/// Uses GPU BLAKE3 implementation for high-throughput hashing.
/// Falls back to CPU if GPU is unavailable or for small objects.
#[cfg(feature = "gpu")]
pub async fn gpu_hash<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Json(req): Json<GpuHashRequest>,
) -> ApiResult<Json<GpuHashResponse>> {
    use warp_gpu::{Blake3Hasher, GpuContext, GpuOp};

    if req.algorithm != "blake3" {
        return Err(ApiError::InvalidRequest(format!(
            "Unsupported algorithm: {}. Only 'blake3' is supported.",
            req.algorithm
        )));
    }

    let object_key = ObjectKey::new(&req.bucket, &req.key)?;
    let data = state.store.get(&object_key).await?;
    let object_size = data.len() as u64;

    let start = Instant::now();

    // Try GPU, fall back to CPU (GPU is typically faster for data > 64KB)
    let use_gpu = data.len() >= 64 * 1024;
    let (hash, gpu_used) = if use_gpu {
        match GpuContext::new() {
            Ok(ctx) => {
                match Blake3Hasher::new(ctx.context().clone()) {
                    Ok(hasher) => match hasher.hash(data.as_ref()) {
                        Ok(h) => (h, true),
                        Err(_) => {
                            // Fallback to CPU
                            let h = blake3::hash(data.as_ref());
                            (*h.as_bytes(), false)
                        }
                    },
                    Err(_) => {
                        // Hasher creation failed, use CPU
                        let h = blake3::hash(data.as_ref());
                        (*h.as_bytes(), false)
                    }
                }
            }
            Err(_) => {
                // No GPU available, use CPU
                let h = blake3::hash(data.as_ref());
                (*h.as_bytes(), false)
            }
        }
    } else {
        // Small data, use CPU directly
        let h = blake3::hash(data.as_ref());
        (*h.as_bytes(), false)
    };

    let elapsed = start.elapsed();
    let time_ms = elapsed.as_millis() as u64;
    let throughput_gbps = if elapsed.as_secs_f64() > 0.0 {
        (object_size as f64 / 1_000_000_000.0) / elapsed.as_secs_f64()
    } else {
        0.0
    };

    Ok(Json(GpuHashResponse {
        hash: hex::encode(hash),
        time_ms,
        throughput_gbps,
        gpu_used,
        object_size,
    }))
}

/// CPU-only hash (when GPU feature is disabled)
#[cfg(not(feature = "gpu"))]
pub async fn gpu_hash<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Json(req): Json<GpuHashRequest>,
) -> ApiResult<Json<GpuHashResponse>> {
    if req.algorithm != "blake3" {
        return Err(ApiError::InvalidRequest(format!(
            "Unsupported algorithm: {}. Only 'blake3' is supported.",
            req.algorithm
        )));
    }

    let object_key = ObjectKey::new(&req.bucket, &req.key)?;
    let data = state.store.get(&object_key).await?;
    let object_size = data.len() as u64;

    let start = Instant::now();
    let hash = blake3::hash(data.as_ref());
    let elapsed = start.elapsed();

    let time_ms = elapsed.as_millis() as u64;
    let throughput_gbps = if elapsed.as_secs_f64() > 0.0 {
        (object_size as f64 / 1_000_000_000.0) / elapsed.as_secs_f64()
    } else {
        0.0
    };

    Ok(Json(GpuHashResponse {
        hash: hex::encode(hash.as_bytes()),
        time_ms,
        throughput_gbps,
        gpu_used: false,
        object_size,
    }))
}

// =============================================================================
// GPU Encryption Operations
// =============================================================================

/// Request for GPU-accelerated encryption
#[derive(Debug, Deserialize)]
pub struct GpuEncryptRequest {
    /// Bucket name
    pub bucket: String,
    /// Object key to encrypt
    pub key: String,
    /// Destination key for encrypted object
    pub dest_key: String,
    /// Encryption key (hex-encoded, 32 bytes)
    pub encryption_key: String,
    /// Nonce (hex-encoded, 12 bytes) - if not provided, random nonce is generated
    pub nonce: Option<String>,
}

/// Response from GPU encryption
#[derive(Debug, Serialize)]
pub struct GpuEncryptResponse {
    /// Destination key where encrypted object is stored
    pub dest_key: String,
    /// Nonce used (hex-encoded)
    pub nonce: String,
    /// Authentication tag (hex-encoded)
    pub tag: String,
    /// Original size in bytes
    pub original_size: u64,
    /// Encrypted size in bytes
    pub encrypted_size: u64,
    /// Time taken in milliseconds
    pub time_ms: u64,
    /// Throughput in GB/s
    pub throughput_gbps: f64,
    /// Whether GPU was used
    pub gpu_used: bool,
}

/// GPU-accelerated encryption of an object
#[cfg(feature = "gpu")]
pub async fn gpu_encrypt<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Json(req): Json<GpuEncryptRequest>,
) -> ApiResult<Json<GpuEncryptResponse>> {
    use warp_gpu::{ChaCha20Poly1305, GpuContext, GpuOp};
    use warp_store::{ObjectData, PutOptions};

    // Parse encryption key
    let key_bytes = hex::decode(&req.encryption_key)
        .map_err(|_| ApiError::InvalidRequest("Invalid encryption key hex".into()))?;
    if key_bytes.len() != 32 {
        return Err(ApiError::InvalidRequest(
            "Encryption key must be 32 bytes".into(),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    // Parse or generate nonce
    let nonce: [u8; 12] = if let Some(nonce_hex) = &req.nonce {
        let nonce_bytes = hex::decode(nonce_hex)
            .map_err(|_| ApiError::InvalidRequest("Invalid nonce hex".into()))?;
        if nonce_bytes.len() != 12 {
            return Err(ApiError::InvalidRequest("Nonce must be 12 bytes".into()));
        }
        let mut n = [0u8; 12];
        n.copy_from_slice(&nonce_bytes);
        n
    } else {
        let mut n = [0u8; 12];
        getrandom::getrandom(&mut n)
            .map_err(|_| ApiError::Internal("Failed to generate nonce".into()))?;
        n
    };

    // Get source object
    let source_key = ObjectKey::new(&req.bucket, &req.key)?;
    let data = state.store.get(&source_key).await?;
    let original_size = data.len() as u64;

    let start = Instant::now();

    // Try GPU encryption (GPU is typically faster for data > 64KB)
    let use_gpu = data.len() >= 64 * 1024;
    let (ciphertext, tag, gpu_used): (Vec<u8>, [u8; 16], bool) = if use_gpu {
        match GpuContext::new() {
            Ok(ctx) => {
                match ChaCha20Poly1305::new(ctx.context().clone()) {
                    Ok(cipher) => match cipher.encrypt(data.as_ref(), &key, &nonce) {
                        Ok(encrypted) => {
                            // Last 16 bytes are the tag
                            let tag_start = encrypted.len() - 16;
                            let mut tag = [0u8; 16];
                            tag.copy_from_slice(&encrypted[tag_start..]);
                            (encrypted[..tag_start].to_vec(), tag, true)
                        }
                        Err(_) => cpu_encrypt(data.as_ref(), &key, &nonce)?,
                    },
                    Err(_) => cpu_encrypt(data.as_ref(), &key, &nonce)?,
                }
            }
            Err(_) => cpu_encrypt(data.as_ref(), &key, &nonce)?,
        }
    } else {
        // Small data, use CPU directly
        cpu_encrypt(data.as_ref(), &key, &nonce)?
    };

    let elapsed = start.elapsed();

    // Store encrypted object
    let dest_key = ObjectKey::new(&req.bucket, &req.dest_key)?;
    let encrypted_size = ciphertext.len() as u64;
    state
        .store
        .put_with_options(
            &dest_key,
            ObjectData::from(ciphertext),
            PutOptions::with_content_type("application/octet-stream"),
        )
        .await?;

    let time_ms = elapsed.as_millis() as u64;
    let throughput_gbps = if elapsed.as_secs_f64() > 0.0 {
        (original_size as f64 / 1_000_000_000.0) / elapsed.as_secs_f64()
    } else {
        0.0
    };

    Ok(Json(GpuEncryptResponse {
        dest_key: req.dest_key,
        nonce: hex::encode(nonce),
        tag: hex::encode(tag),
        original_size,
        encrypted_size,
        time_ms,
        throughput_gbps,
        gpu_used,
    }))
}

#[cfg(feature = "gpu")]
fn cpu_encrypt(
    data: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> Result<(Vec<u8>, [u8; 16], bool), ApiError> {
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305 as CpuChaCha, KeyInit};

    let cipher = CpuChaCha::new(GenericArray::from_slice(key));
    let mut buffer = data.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), &[], &mut buffer)
        .map_err(|_| ApiError::Internal("Encryption failed".into()))?;

    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(tag.as_slice());

    Ok((buffer, tag_bytes, false))
}

/// CPU-only encryption (when GPU feature is disabled)
#[cfg(not(feature = "gpu"))]
pub async fn gpu_encrypt<B: StorageBackend>(
    State(_state): State<AppState<B>>,
    Json(_req): Json<GpuEncryptRequest>,
) -> ApiResult<Json<GpuEncryptResponse>> {
    Err(ApiError::InvalidRequest(
        "GPU encryption requires the 'gpu' feature to be enabled".into(),
    ))
}

// =============================================================================
// GPU Capabilities and Stats
// =============================================================================

/// GPU device capabilities
#[derive(Debug, Serialize)]
pub struct GpuCapabilities {
    /// Whether GPU is available
    pub available: bool,
    /// Device name
    pub device_name: Option<String>,
    /// Compute capability (e.g., "8.9" for RTX 4090)
    pub compute_capability: Option<String>,
    /// Total GPU memory in bytes
    pub total_memory: Option<u64>,
    /// Free GPU memory in bytes
    pub free_memory: Option<u64>,
    /// Maximum threads per block
    pub max_threads_per_block: Option<u32>,
    /// Number of streaming multiprocessors
    pub multiprocessor_count: Option<u32>,
    /// Estimated CUDA cores
    pub estimated_cuda_cores: Option<u32>,
}

/// Get GPU capabilities
#[cfg(feature = "gpu")]
pub async fn gpu_capabilities<B: StorageBackend>(
    State(_state): State<AppState<B>>,
) -> Json<GpuCapabilities> {
    use warp_gpu::GpuContext;

    match GpuContext::new() {
        Ok(ctx) => {
            let caps = ctx.capabilities();
            let device_name = ctx.device_name().ok();
            let (major, minor) = caps.compute_capability;
            Json(GpuCapabilities {
                available: true,
                device_name,
                compute_capability: Some(format!("{}.{}", major, minor)),
                total_memory: Some(caps.total_memory as u64),
                free_memory: ctx.free_memory().ok().map(|m| m as u64),
                max_threads_per_block: Some(caps.max_threads_per_block as u32),
                multiprocessor_count: Some(caps.multiprocessor_count as u32),
                estimated_cuda_cores: Some(caps.estimated_cuda_cores() as u32),
            })
        }
        Err(_) => Json(GpuCapabilities {
            available: false,
            device_name: None,
            compute_capability: None,
            total_memory: None,
            free_memory: None,
            max_threads_per_block: None,
            multiprocessor_count: None,
            estimated_cuda_cores: None,
        }),
    }
}

#[cfg(not(feature = "gpu"))]
pub async fn gpu_capabilities<B: StorageBackend>(
    State(_state): State<AppState<B>>,
) -> Json<GpuCapabilities> {
    Json(GpuCapabilities {
        available: false,
        device_name: None,
        compute_capability: None,
        total_memory: None,
        free_memory: None,
        max_threads_per_block: None,
        multiprocessor_count: None,
        estimated_cuda_cores: None,
    })
}

/// GPU operation statistics
#[derive(Debug, Serialize)]
pub struct GpuStats {
    /// Whether GPU feature is enabled
    pub gpu_enabled: bool,
    /// Whether GPU is available
    pub gpu_available: bool,
    /// Recommended minimum size for GPU operations (bytes)
    pub gpu_threshold_bytes: usize,
    /// Supported operations
    pub supported_ops: Vec<String>,
}

/// Get GPU stats
pub async fn gpu_stats<B: StorageBackend>(State(_state): State<AppState<B>>) -> Json<GpuStats> {
    #[cfg(feature = "gpu")]
    let (gpu_enabled, gpu_available) = {
        use warp_gpu::GpuContext;
        (true, GpuContext::new().is_ok())
    };

    #[cfg(not(feature = "gpu"))]
    let (gpu_enabled, gpu_available) = (false, false);

    Json(GpuStats {
        gpu_enabled,
        gpu_available,
        gpu_threshold_bytes: 65536, // 64KB default threshold
        supported_ops: vec!["blake3".to_string(), "chacha20-poly1305".to_string()],
    })
}
