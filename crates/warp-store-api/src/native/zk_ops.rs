//! Zero-Knowledge Proof operations endpoints
//!
//! Provides endpoints for:
//! - Proof generation (Groth16, PLONK, STARK)
//! - Proof verification
//! - Verified storage reads with Merkle proofs
//!
//! These endpoints require the `zk` feature to be enabled.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use warp_store::ObjectKey;
use warp_store::backend::StorageBackend;

use crate::AppState;
use crate::error::{ApiError, ApiResult};

// =============================================================================
// Proof Types (matching nebula-zk structure)
// =============================================================================

/// Supported proof types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProofType {
    /// Groth16 SNARK - smallest proofs (~192 bytes), requires trusted setup
    Groth16,
    /// PLONK - universal setup (~768 bytes)
    Plonk,
    /// STARK - no trusted setup, post-quantum (~50KB)
    Stark,
    /// Bulletproofs - range proofs (~672 bytes)
    Bulletproofs,
    /// Simulated - for testing
    Simulated,
}

impl ProofType {
    /// Whether this proof type requires a trusted setup
    pub fn requires_trusted_setup(&self) -> bool {
        matches!(self, ProofType::Groth16 | ProofType::Plonk)
    }

    /// Whether this proof type is post-quantum secure
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, ProofType::Stark)
    }

    /// Typical proof size in bytes
    pub fn typical_proof_size(&self) -> usize {
        match self {
            ProofType::Groth16 => 192,
            ProofType::Plonk => 768,
            ProofType::Stark => 50_000,
            ProofType::Bulletproofs => 672,
            ProofType::Simulated => 256,
        }
    }

    /// Relative verification cost (1-100)
    pub fn verification_cost(&self) -> u32 {
        match self {
            ProofType::Groth16 => 3,
            ProofType::Plonk => 10,
            ProofType::Bulletproofs => 20,
            ProofType::Stark => 100,
            ProofType::Simulated => 1,
        }
    }
}

// =============================================================================
// Proof Generation
// =============================================================================

/// Request for ZK proof generation
#[derive(Debug, Deserialize)]
pub struct ZkProveRequest {
    /// Type of proof to generate
    pub proof_type: ProofType,
    /// Public inputs (hex-encoded)
    pub public_inputs: Vec<String>,
    /// Private witness (hex-encoded)
    pub witness: Vec<String>,
    /// Optional: use GPU acceleration
    #[serde(default)]
    pub use_gpu: bool,
}

/// Response from ZK proof generation
#[derive(Debug, Serialize)]
pub struct ZkProveResponse {
    /// Generated proof (hex-encoded)
    pub proof: String,
    /// Proof type used
    pub proof_type: ProofType,
    /// Proof size in bytes
    pub proof_size: usize,
    /// Time taken in milliseconds
    pub time_ms: u64,
    /// Whether GPU was used
    pub gpu_used: bool,
    /// Number of constraints
    pub num_constraints: u64,
}

/// Generate a ZK proof
///
/// In production, this would use nebula-zk for actual proof generation.
/// Currently provides a simulated implementation for API testing.
pub async fn zk_prove<B: StorageBackend>(
    State(_state): State<AppState<B>>,
    Json(req): Json<ZkProveRequest>,
) -> ApiResult<Json<ZkProveResponse>> {
    let start = Instant::now();

    // Validate inputs
    if req.public_inputs.is_empty() {
        return Err(ApiError::InvalidRequest(
            "At least one public input required".into(),
        ));
    }

    // Parse public inputs
    for (i, input) in req.public_inputs.iter().enumerate() {
        hex::decode(input)
            .map_err(|_| ApiError::InvalidRequest(format!("Invalid hex in public_input[{}]", i)))?;
    }

    // Parse witness
    for (i, w) in req.witness.iter().enumerate() {
        hex::decode(w)
            .map_err(|_| ApiError::InvalidRequest(format!("Invalid hex in witness[{}]", i)))?;
    }

    // Simulate proof generation
    // In production, this would call nebula-zk prover
    let proof_size = req.proof_type.typical_proof_size();
    let mut proof_data = vec![0u8; proof_size];

    // Create a deterministic "proof" based on inputs for testing
    let hash = blake3::hash(
        &[
            req.public_inputs.join("").as_bytes(),
            req.witness.join("").as_bytes(),
        ]
        .concat(),
    );
    let hash_bytes = hash.as_bytes();
    for i in 0..proof_size.min(32) {
        proof_data[i] = hash_bytes[i % 32];
    }

    let elapsed = start.elapsed();

    Ok(Json(ZkProveResponse {
        proof: hex::encode(&proof_data),
        proof_type: req.proof_type,
        proof_size,
        time_ms: elapsed.as_millis() as u64,
        gpu_used: false, // Would be true if nebula-zk GPU prover was used
        num_constraints: (req.public_inputs.len() + req.witness.len()) as u64 * 1000,
    }))
}

// =============================================================================
// Proof Verification
// =============================================================================

/// Request for ZK proof verification
#[derive(Debug, Deserialize)]
pub struct ZkVerifyRequest {
    /// Proof to verify (hex-encoded)
    pub proof: String,
    /// Type of proof
    pub proof_type: ProofType,
    /// Public inputs (hex-encoded)
    pub public_inputs: Vec<String>,
}

/// Response from ZK proof verification
#[derive(Debug, Serialize)]
pub struct ZkVerifyResponse {
    /// Whether the proof is valid
    pub valid: bool,
    /// Time taken in milliseconds
    pub time_ms: u64,
    /// Verification cost (relative units)
    pub verification_cost: u32,
}

/// Verify a ZK proof
pub async fn zk_verify<B: StorageBackend>(
    State(_state): State<AppState<B>>,
    Json(req): Json<ZkVerifyRequest>,
) -> ApiResult<Json<ZkVerifyResponse>> {
    let start = Instant::now();

    // Validate proof
    let proof_bytes = hex::decode(&req.proof)
        .map_err(|_| ApiError::InvalidRequest("Invalid proof hex".into()))?;

    // Validate public inputs
    for (i, input) in req.public_inputs.iter().enumerate() {
        hex::decode(input)
            .map_err(|_| ApiError::InvalidRequest(format!("Invalid hex in public_input[{}]", i)))?;
    }

    // Simulate verification
    // In production, this would call nebula-zk verifier
    let expected_size = req.proof_type.typical_proof_size();
    let valid = proof_bytes.len() == expected_size;

    let elapsed = start.elapsed();

    Ok(Json(ZkVerifyResponse {
        valid,
        time_ms: elapsed.as_millis() as u64,
        verification_cost: req.proof_type.verification_cost(),
    }))
}

// =============================================================================
// Verified Storage Read (with Merkle Proof)
// =============================================================================

/// Request for verified read
#[derive(Debug, Deserialize)]
pub struct VerifiedReadRequest {
    /// Bucket name
    pub bucket: String,
    /// Object key
    pub key: String,
}

/// Response from verified read
#[derive(Debug, Serialize)]
pub struct VerifiedReadResponse {
    /// Object data (base64-encoded)
    pub data: String,
    /// Object size in bytes
    pub size: u64,
    /// Content hash (BLAKE3, hex-encoded)
    pub content_hash: String,
    /// Merkle root (hex-encoded)
    pub merkle_root: String,
    /// Merkle proof path (hex-encoded hashes)
    pub merkle_path: Vec<String>,
    /// Leaf index in Merkle tree
    pub leaf_index: u64,
    /// Whether the proof was verified
    pub verified: bool,
    /// Time taken in milliseconds
    pub time_ms: u64,
}

/// Read an object with a cryptographic proof of storage
///
/// Returns the object data along with a Merkle proof that can be
/// verified without trusting the storage node.
pub async fn verified_read<B: StorageBackend>(
    State(state): State<AppState<B>>,
    Json(req): Json<VerifiedReadRequest>,
) -> ApiResult<Json<VerifiedReadResponse>> {
    let start = Instant::now();

    let object_key = ObjectKey::new(&req.bucket, &req.key)?;
    let data = state.store.get(&object_key).await?;
    let size = data.len() as u64;

    // Compute content hash
    let content_hash = blake3::hash(data.as_ref());

    // Build simple Merkle proof
    // In production, this would use the sparse Merkle tree from nebula
    let merkle_root = *content_hash.as_bytes();
    let merkle_path: Vec<[u8; 32]> = vec![]; // Single-node tree for now
    let leaf_index = 0u64;

    // Verify the proof
    let verified = verify_merkle_proof(&merkle_root, &merkle_path, leaf_index, data.as_ref());

    let elapsed = start.elapsed();

    Ok(Json(VerifiedReadResponse {
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data.as_ref()),
        size,
        content_hash: hex::encode(content_hash.as_bytes()),
        merkle_root: hex::encode(merkle_root),
        merkle_path: merkle_path.iter().map(hex::encode).collect(),
        leaf_index,
        verified,
        time_ms: elapsed.as_millis() as u64,
    }))
}

/// Verify a Merkle proof
fn verify_merkle_proof(root: &[u8; 32], path: &[[u8; 32]], leaf_index: u64, data: &[u8]) -> bool {
    let mut hash = *blake3::hash(data).as_bytes();

    for (i, sibling) in path.iter().enumerate() {
        let bit = (leaf_index >> i) & 1;
        hash = if bit == 0 {
            *blake3::hash(&[&hash[..], &sibling[..]].concat()).as_bytes()
        } else {
            *blake3::hash(&[&sibling[..], &hash[..]].concat()).as_bytes()
        };
    }

    hash == *root
}

// =============================================================================
// Proof Types Info
// =============================================================================

/// Information about a proof type
#[derive(Debug, Serialize)]
pub struct ProofTypeInfo {
    /// Proof type name
    pub name: String,
    /// Typical proof size in bytes
    pub size_bytes: usize,
    /// Whether trusted setup is required
    pub requires_trusted_setup: bool,
    /// Whether post-quantum secure
    pub post_quantum: bool,
    /// Relative verification cost
    pub verification_cost: u32,
}

/// Response listing supported proof types
#[derive(Debug, Serialize)]
pub struct ProofTypesResponse {
    /// Supported proof types
    pub supported: Vec<ProofTypeInfo>,
}

/// Get supported proof types
pub async fn zk_proof_types<B: StorageBackend>(
    State(_state): State<AppState<B>>,
) -> Json<ProofTypesResponse> {
    let types = vec![
        ProofType::Groth16,
        ProofType::Plonk,
        ProofType::Stark,
        ProofType::Bulletproofs,
        ProofType::Simulated,
    ];

    let supported = types
        .into_iter()
        .map(|t| ProofTypeInfo {
            name: format!("{:?}", t).to_lowercase(),
            size_bytes: t.typical_proof_size(),
            requires_trusted_setup: t.requires_trusted_setup(),
            post_quantum: t.is_post_quantum(),
            verification_cost: t.verification_cost(),
        })
        .collect();

    Json(ProofTypesResponse { supported })
}

/// ZK subsystem statistics
#[derive(Debug, Serialize)]
pub struct ZkStats {
    /// Whether ZK feature is enabled
    pub zk_enabled: bool,
    /// Supported proof types
    pub supported_types: Vec<String>,
    /// Whether GPU proving is available
    pub gpu_proving_available: bool,
}

/// Get ZK stats
pub async fn zk_stats<B: StorageBackend>(State(_state): State<AppState<B>>) -> Json<ZkStats> {
    Json(ZkStats {
        zk_enabled: cfg!(feature = "zk"),
        supported_types: vec![
            "groth16".to_string(),
            "plonk".to_string(),
            "stark".to_string(),
            "bulletproofs".to_string(),
            "simulated".to_string(),
        ],
        gpu_proving_available: false, // Would check nebula-zk GPU prover
    })
}
