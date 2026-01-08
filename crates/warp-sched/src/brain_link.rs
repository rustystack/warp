//! SLAI Brain-Link Integration for GPU-Aware Chunk Scheduling
//!
//! This module integrates SLAI (Scalable Lightweight AI-infrastructure) with
//! warp-sched to provide GPU-aware chunk placement and transfer scheduling.
//!
//! # Features
//!
//! - **Transport-Aware Placement**: Uses SLAI's network topology for optimal
//!   chunk routing based on available transports (`NVLink`, RDMA, InfiniBand)
//! - **GPU Memory Awareness**: Considers GPU memory availability when placing
//!   chunks for GPU-direct transfers
//! - **NUMA Locality**: Optimizes chunk placement based on NUMA topology
//! - **Communication Pattern Optimization**: Selects transfer strategies based
//!   on collective operation patterns (scatter, gather, all-reduce)
//!
//! # Example
//!
//! ```ignore
//! use warp_sched::brain_link::{BrainLink, ChunkPlacementRequest};
//!
//! let brain_link = BrainLink::new().await?;
//!
//! let request = ChunkPlacementRequest {
//!     chunk_hash: [0u8; 32],
//!     chunk_size: 1024 * 1024,
//!     target_gpu: Some(0),
//!     prefer_local: true,
//!     pattern: CommunicationPattern::Scatter,
//! };
//!
//! let placement = brain_link.request_placement(request).await?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::Result;
use crate::SchedError;
use crate::types::{ChunkId, EdgeIdx};

/// Communication pattern for chunk transfers.
///
/// Maps to collective operation patterns for optimized routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommunicationPattern {
    /// Scatter: One-to-many distribution.
    Scatter,
    /// Gather: Many-to-one collection.
    Gather,
    /// Broadcast: One-to-all.
    Broadcast,
    /// `AllGather`: All-to-all collection.
    AllGather,
    /// `AllReduce`: Collective reduction.
    AllReduce,
    /// `PointToPoint`: Direct transfer between two edges.
    PointToPoint,
    /// Pipeline: Sequential chain of transfers.
    Pipeline,
}

impl CommunicationPattern {
    /// Get bandwidth requirement factor (0.0 - 1.0).
    #[must_use]
    pub const fn bandwidth_factor(&self) -> f64 {
        match self {
            Self::AllReduce => 1.0,
            Self::AllGather => 0.9,
            Self::Scatter => 0.7,
            Self::Gather => 0.7,
            Self::Broadcast => 0.6,
            Self::Pipeline => 0.5,
            Self::PointToPoint => 0.3,
        }
    }

    /// Check if pattern benefits from locality.
    #[must_use]
    pub const fn benefits_from_locality(&self) -> bool {
        matches!(
            self,
            Self::AllReduce | Self::AllGather | Self::Scatter | Self::Gather
        )
    }
}

/// Transport type for chunk transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportType {
    /// TCP/IP transport.
    Tcp,
    /// QUIC transport.
    Quic,
    /// RDMA (Remote Direct Memory Access).
    Rdma,
    /// InfiniBand.
    InfiniBand,
    /// `NVLink` (GPU-to-GPU).
    NvLink,
    /// `PCIe`.
    Pcie,
    /// Shared memory (same node).
    SharedMemory,
    /// GPU-Direct Storage.
    GpuDirect,
    /// DPU inline processing (zero-copy on network path).
    DpuInline,
    /// DPU RDMA (RDMA with DPU inline processing).
    DpuRdma,
}

impl TransportType {
    /// Get typical latency in microseconds.
    #[must_use]
    pub const fn latency_us(&self) -> u32 {
        match self {
            Self::SharedMemory => 1,
            Self::NvLink => 2,
            Self::DpuInline => 3, // DPU inline very low latency
            Self::DpuRdma => 5,   // DPU RDMA slightly higher
            Self::Pcie => 5,
            Self::GpuDirect => 8,
            Self::Rdma => 10,
            Self::InfiniBand => 15,
            Self::Quic => 100,
            Self::Tcp => 150,
        }
    }

    /// Get typical bandwidth in Gbps.
    #[must_use]
    pub const fn bandwidth_gbps(&self) -> u32 {
        match self {
            Self::NvLink => 600,
            Self::DpuRdma => 400, // BlueField-3 400Gbps
            Self::SharedMemory => 400,
            Self::InfiniBand => 400,
            Self::DpuInline => 200, // DPU with inline processing
            Self::GpuDirect => 200,
            Self::Rdma => 200,
            Self::Pcie => 128,
            Self::Quic => 100,
            Self::Tcp => 100,
        }
    }

    /// Check if this is a high-performance transport.
    #[must_use]
    pub const fn is_high_performance(&self) -> bool {
        matches!(
            self,
            Self::NvLink
                | Self::SharedMemory
                | Self::InfiniBand
                | Self::Rdma
                | Self::GpuDirect
                | Self::DpuInline
                | Self::DpuRdma
        )
    }

    /// Check if this transport uses DPU.
    #[must_use]
    pub const fn uses_dpu(&self) -> bool {
        matches!(self, Self::DpuInline | Self::DpuRdma)
    }

    /// Check if this transport supports inline processing.
    #[must_use]
    pub const fn supports_inline_processing(&self) -> bool {
        matches!(self, Self::DpuInline | Self::DpuRdma)
    }
}

/// DPU type identifier for scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum DpuType {
    /// No DPU (CPU fallback).
    #[default]
    None,
    /// NVIDIA `BlueField` DPU.
    BlueField,
    /// AMD Pensando DPU.
    Pensando,
    /// Intel IPU.
    IntelIpu,
}

impl DpuType {
    /// Check if this is a real DPU (not None).
    #[must_use]
    pub const fn is_hardware(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// DPU capabilities for scheduling decisions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpuCapabilities {
    /// DPU has inline crypto acceleration.
    pub has_inline_crypto: bool,
    /// DPU has inline compression acceleration.
    pub has_inline_compress: bool,
    /// DPU has erasure coding acceleration.
    pub has_inline_ec: bool,
    /// DPU has RDMA support.
    pub has_rdma: bool,
    /// Network bandwidth in Gbps.
    pub network_bandwidth_gbps: u32,
    /// DPU generation (e.g., 3 for BlueField-3).
    pub generation: u32,
}

impl DpuCapabilities {
    /// Create capabilities for BlueField-3.
    #[must_use]
    pub const fn bluefield3() -> Self {
        Self {
            has_inline_crypto: true,
            has_inline_compress: true,
            has_inline_ec: true,
            has_rdma: true,
            network_bandwidth_gbps: 400,
            generation: 3,
        }
    }

    /// Check if any DPU acceleration is available.
    #[must_use]
    pub const fn has_any_acceleration(&self) -> bool {
        self.has_inline_crypto || self.has_inline_compress || self.has_inline_ec
    }

    /// Calculate DPU score for placement (higher = better).
    #[must_use]
    pub fn score(&self) -> f64 {
        let mut score = 0.0;
        if self.has_inline_crypto {
            score += 10.0;
        }
        if self.has_inline_compress {
            score += 10.0;
        }
        if self.has_inline_ec {
            score += 5.0;
        }
        if self.has_rdma {
            score += 15.0;
        }
        score += (f64::from(self.network_bandwidth_gbps) / 100.0).min(10.0);
        score
    }
}

/// Chunk placement request.
#[derive(Debug, Clone)]
pub struct ChunkPlacementRequest {
    /// Chunk ID.
    pub chunk_id: ChunkId,
    /// Chunk hash (32-byte BLAKE3) for logging.
    pub chunk_hash: [u8; 32],
    /// Chunk size in bytes.
    pub chunk_size: u64,
    /// Target GPU index (if GPU-direct).
    pub target_gpu: Option<u32>,
    /// Prefer local storage.
    pub prefer_local: bool,
    /// Communication pattern.
    pub pattern: CommunicationPattern,
    /// Priority (0-255, higher = more urgent).
    pub priority: u8,
    /// Required transport type.
    pub required_transport: Option<TransportType>,
}

impl Default for ChunkPlacementRequest {
    fn default() -> Self {
        Self {
            chunk_id: ChunkId(0),
            chunk_hash: [0u8; 32],
            chunk_size: 0,
            target_gpu: None,
            prefer_local: true,
            pattern: CommunicationPattern::PointToPoint,
            priority: 100,
            required_transport: None,
        }
    }
}

/// Chunk placement decision.
#[derive(Debug, Clone)]
pub struct ChunkPlacement {
    /// Chunk ID.
    pub chunk_id: ChunkId,
    /// Selected source edges (ordered by preference).
    pub source_edges: Vec<EdgeIdx>,
    /// Selected transport type.
    pub transport: TransportType,
    /// Target GPU (if applicable).
    pub target_gpu: Option<u32>,
    /// Estimated transfer time in milliseconds.
    pub estimated_time_ms: u32,
    /// Placement score (higher = better).
    pub score: f64,
    /// NUMA node affinity.
    pub numa_node: Option<u32>,
}

/// Edge node information for placement decisions.
#[derive(Debug, Clone)]
pub struct EdgeNodeInfo {
    /// Edge index.
    pub edge_idx: EdgeIdx,
    /// Node ID.
    pub node_id: String,
    /// Available GPUs.
    pub gpu_count: u32,
    /// GPU memory available (bytes).
    pub gpu_memory_available: u64,
    /// Supported transports.
    pub transports: Vec<TransportType>,
    /// NUMA nodes.
    pub numa_nodes: u32,
    /// Current load (0.0 - 1.0).
    pub load: f64,
    /// Is healthy.
    pub healthy: bool,
    /// Number of DPUs available.
    pub dpu_count: u32,
    /// DPU type (if available).
    pub dpu_type: DpuType,
    /// DPU capabilities.
    pub dpu_capabilities: DpuCapabilities,
}

impl EdgeNodeInfo {
    /// Create a new edge node info.
    pub fn new(edge_idx: EdgeIdx, node_id: impl Into<String>) -> Self {
        Self {
            edge_idx,
            node_id: node_id.into(),
            gpu_count: 0,
            gpu_memory_available: 0,
            transports: vec![TransportType::Tcp],
            numa_nodes: 1,
            load: 0.0,
            healthy: true,
            dpu_count: 0,
            dpu_type: DpuType::None,
            dpu_capabilities: DpuCapabilities::default(),
        }
    }

    /// Set GPU count.
    #[must_use]
    pub const fn with_gpus(mut self, count: u32, memory_available: u64) -> Self {
        self.gpu_count = count;
        self.gpu_memory_available = memory_available;
        self
    }

    /// Add transport.
    #[must_use]
    pub fn with_transport(mut self, transport: TransportType) -> Self {
        if !self.transports.contains(&transport) {
            self.transports.push(transport);
        }
        self
    }

    /// Set DPU configuration.
    #[must_use]
    pub fn with_dpu(
        mut self,
        count: u32,
        dpu_type: DpuType,
        capabilities: DpuCapabilities,
    ) -> Self {
        self.dpu_count = count;
        self.dpu_type = dpu_type;
        // Auto-add DPU transports based on capabilities (before move)
        if capabilities.has_rdma && !self.transports.contains(&TransportType::DpuRdma) {
            self.transports.push(TransportType::DpuRdma);
        }
        if capabilities.has_any_acceleration()
            && !self.transports.contains(&TransportType::DpuInline)
        {
            self.transports.push(TransportType::DpuInline);
        }
        self.dpu_capabilities = capabilities;
        self
    }

    /// Check if node has high-performance transport.
    #[must_use]
    pub fn has_high_perf_transport(&self) -> bool {
        self.transports
            .iter()
            .any(TransportType::is_high_performance)
    }

    /// Check if node has DPU capabilities.
    #[must_use]
    pub const fn has_dpu(&self) -> bool {
        self.dpu_count > 0 && self.dpu_type.is_hardware()
    }

    /// Check if node has DPU inline processing.
    #[must_use]
    pub const fn has_dpu_inline(&self) -> bool {
        self.has_dpu() && self.dpu_capabilities.has_any_acceleration()
    }

    /// Calculate node score for placement.
    #[must_use]
    pub fn placement_score(&self, request: &ChunkPlacementRequest) -> f64 {
        if !self.healthy {
            return 0.0;
        }

        let mut score = 100.0;

        // Penalize high load
        score -= self.load * 30.0;

        // Bonus for GPU availability if GPU-direct requested
        if request.target_gpu.is_some() && self.gpu_count > 0 {
            score += 20.0;
            // Bonus for sufficient GPU memory
            if self.gpu_memory_available >= request.chunk_size {
                score += 10.0;
            }
        }

        // Bonus for high-performance transport
        if self.has_high_perf_transport() {
            score += 15.0;
        }

        // Bonus for DPU availability and capabilities
        if self.has_dpu() {
            // Base DPU bonus
            score += 20.0;
            // Add DPU capability score (0-50 range)
            score += self.dpu_capabilities.score();
            // Extra bonus for DPU transport matching required transport
            if let Some(required) = request.required_transport {
                if required.uses_dpu() && self.transports.contains(&required) {
                    score += 30.0;
                }
            }
        }

        // Bonus for required transport
        if let Some(required) = request.required_transport {
            if self.transports.contains(&required) {
                score += 25.0;
            } else {
                score -= 50.0; // Major penalty
            }
        }

        score.max(0.0)
    }
}

/// Network link between edges.
#[derive(Debug, Clone)]
pub struct NetworkLink {
    /// Source edge.
    pub source: EdgeIdx,
    /// Destination edge.
    pub destination: EdgeIdx,
    /// Available transports.
    pub transports: Vec<TransportType>,
    /// Best transport (lowest latency).
    pub best_transport: TransportType,
    /// Measured bandwidth (bytes/sec).
    pub bandwidth_bps: u64,
    /// Measured latency (microseconds).
    pub latency_us: u32,
    /// Link is healthy.
    pub healthy: bool,
}

impl NetworkLink {
    /// Create a new link.
    #[must_use]
    pub fn new(source: EdgeIdx, destination: EdgeIdx, transports: Vec<TransportType>) -> Self {
        let best = transports
            .iter()
            .min_by_key(|t| t.latency_us())
            .copied()
            .unwrap_or(TransportType::Tcp);

        Self {
            source,
            destination,
            transports,
            best_transport: best,
            bandwidth_bps: u64::from(best.bandwidth_gbps()) * 1_000_000_000 / 8,
            latency_us: best.latency_us(),
            healthy: true,
        }
    }

    /// Calculate link score (higher = better).
    #[must_use]
    pub fn score(&self) -> f64 {
        if !self.healthy {
            return 0.0;
        }

        let bw_score = (self.bandwidth_bps as f64 / 1e9).min(100.0);
        let latency_score = 1000.0 / (f64::from(self.latency_us) + 1.0);

        bw_score * 0.6 + latency_score * 0.4
    }
}

/// Brain-Link scheduler integration.
///
/// Provides GPU-aware chunk placement using SLAI's transport topology
/// and fair-share scheduling.
///
/// # Concurrency Model
///
/// Uses eventual consistency for placement decisions:
/// - Edge and link state is protected by `RwLock`
/// - Placement queries may see slightly stale data during concurrent updates
/// - This is acceptable since placement decisions are advisory and will be
///   re-evaluated if the chosen edge becomes unavailable
/// - For correctness, the caller should handle placement failures gracefully
///   and retry with fresh data if needed
pub struct BrainLink {
    /// Edge nodes.
    edges: Arc<RwLock<HashMap<EdgeIdx, EdgeNodeInfo>>>,
    /// Network links.
    links: Arc<RwLock<HashMap<(EdgeIdx, EdgeIdx), NetworkLink>>>,
    /// Local edge index.
    local_edge: EdgeIdx,
    /// SLAI integration (when feature enabled).
    #[cfg(feature = "slai")]
    slai: Option<Arc<RwLock<slai::EmbeddedSlai>>>,
}

impl BrainLink {
    /// Create a new Brain-Link instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            edges: Arc::new(RwLock::new(HashMap::new())),
            links: Arc::new(RwLock::new(HashMap::new())),
            local_edge: EdgeIdx(0),
            #[cfg(feature = "slai")]
            slai: None,
        }
    }

    /// Create with local edge.
    #[must_use]
    pub const fn with_local_edge(mut self, edge: EdgeIdx) -> Self {
        self.local_edge = edge;
        self
    }

    /// Initialize with SLAI runtime.
    ///
    /// # Errors
    ///
    /// This function is designed to never return an error. If SLAI initialization
    /// fails, it logs a warning and continues with local scheduling.
    #[cfg(feature = "slai")]
    pub async fn init_slai(&mut self) -> Result<()> {
        match slai::EmbeddedSlai::new() {
            Ok(slai) => {
                info!("SLAI runtime initialized");
                self.slai = Some(Arc::new(RwLock::new(slai)));
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "Failed to initialize SLAI, using local scheduling");
                Ok(())
            }
        }
    }

    /// Initialize without SLAI.
    ///
    /// # Errors
    ///
    /// This function never returns an error.
    #[cfg(not(feature = "slai"))]
    #[allow(clippy::unused_async)]
    pub async fn init_slai(&mut self) -> Result<()> {
        info!("SLAI not available (feature not enabled)");
        Ok(())
    }

    /// Register an edge node.
    pub async fn register_edge(&self, info: EdgeNodeInfo) {
        let edge_idx = info.edge_idx;
        self.edges.write().await.insert(edge_idx, info);
        debug!(edge = edge_idx.0, "Registered edge node");
    }

    /// Unregister an edge node.
    pub async fn unregister_edge(&self, edge: EdgeIdx) {
        self.edges.write().await.remove(&edge);
        // Remove associated links
        self.links
            .write()
            .await
            .retain(|(src, dst), _| *src != edge && *dst != edge);
        debug!(edge = edge.0, "Unregistered edge node");
    }

    /// Add a network link.
    pub async fn add_link(&self, link: NetworkLink) {
        let key = (link.source, link.destination);
        self.links.write().await.insert(key, link);
    }

    /// Request chunk placement.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No edges are registered
    /// - No suitable edges are found for the request
    pub async fn request_placement(
        &self,
        request: ChunkPlacementRequest,
    ) -> Result<ChunkPlacement> {
        let edges = self.edges.read().await;

        if edges.is_empty() {
            return Err(SchedError::InvalidConfig("No edges registered".into()));
        }

        // Score and rank candidate edges
        let mut candidates: Vec<_> = edges
            .values()
            .filter(|e| e.healthy)
            .map(|e| (e.edge_idx, e.placement_score(&request)))
            .filter(|(_, score)| *score > 0.0)
            .collect();

        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        if candidates.is_empty() {
            return Err(SchedError::InvalidConfig("No suitable edges found".into()));
        }

        // Take top 3 candidates
        let source_edges: Vec<EdgeIdx> = candidates.iter().take(3).map(|(idx, _)| *idx).collect();

        // Determine best transport
        let links = self.links.read().await;
        let transport = self.select_transport(&source_edges, &request, &links);

        // Get best edge info for estimates
        let best_edge = edges.get(&source_edges[0]);

        // Calculate estimated transfer time
        let estimated_time_ms = self.estimate_transfer_time(
            request.chunk_size,
            transport,
            best_edge.map_or(0.0, |e| e.load),
        );

        // Get NUMA node if available
        let numa_node = best_edge.map(|e| e.numa_nodes.saturating_sub(1));

        let placement = ChunkPlacement {
            chunk_id: request.chunk_id,
            source_edges,
            transport,
            target_gpu: request.target_gpu,
            estimated_time_ms,
            score: candidates[0].1,
            numa_node,
        };

        debug!(
            chunk_id = request.chunk_id.0,
            chunk_hash = ?hex::encode(&request.chunk_hash[..8]),
            edges = ?placement.source_edges.iter().map(|e| e.0).collect::<Vec<_>>(),
            transport = ?transport,
            "Placement decision"
        );

        Ok(placement)
    }

    /// Request batch placement for multiple chunks.
    ///
    /// # Errors
    ///
    /// This function never returns an error. Individual placement failures are
    /// logged as warnings and skipped.
    pub async fn request_batch_placement(
        &self,
        requests: Vec<ChunkPlacementRequest>,
    ) -> Result<Vec<ChunkPlacement>> {
        let mut placements = Vec::with_capacity(requests.len());

        for request in requests {
            match self.request_placement(request).await {
                Ok(placement) => placements.push(placement),
                Err(e) => {
                    warn!(error = %e, "Failed to place chunk");
                }
            }
        }

        Ok(placements)
    }

    /// Select best transport for transfer.
    fn select_transport(
        &self,
        sources: &[EdgeIdx],
        request: &ChunkPlacementRequest,
        links: &HashMap<(EdgeIdx, EdgeIdx), NetworkLink>,
    ) -> TransportType {
        // If required transport specified, use it
        if let Some(required) = request.required_transport {
            return required;
        }

        // Check if local transfer
        if sources.contains(&self.local_edge) {
            return TransportType::SharedMemory;
        }

        // Find best transport from available links
        for source in sources {
            let key = (*source, self.local_edge);
            if let Some(link) = links.get(&key) {
                if link.healthy {
                    return link.best_transport;
                }
            }
        }

        // Default to TCP
        TransportType::Tcp
    }

    /// Estimate transfer time in milliseconds.
    fn estimate_transfer_time(&self, size: u64, transport: TransportType, load: f64) -> u32 {
        let bandwidth_bps = u64::from(transport.bandwidth_gbps()) * 1_000_000_000 / 8;
        let base_time_us = (size * 1_000_000) / bandwidth_bps.max(1);

        // Add latency
        let latency = u64::from(transport.latency_us());

        // Apply load factor (higher load = slower)
        let load_factor = load.mul_add(0.5, 1.0);

        let total_us = ((base_time_us + latency) as f64 * load_factor) as u64;
        (total_us / 1000).max(1) as u32
    }

    /// Update edge load.
    pub async fn update_edge_load(&self, edge: EdgeIdx, load: f64) {
        if let Some(info) = self.edges.write().await.get_mut(&edge) {
            info.load = load.clamp(0.0, 1.0);
        }
    }

    /// Mark edge as unhealthy.
    pub async fn mark_edge_unhealthy(&self, edge: EdgeIdx) {
        if let Some(info) = self.edges.write().await.get_mut(&edge) {
            info.healthy = false;
            warn!(edge = edge.0, "Edge marked unhealthy");
        }
    }

    /// Mark edge as healthy.
    pub async fn mark_edge_healthy(&self, edge: EdgeIdx) {
        if let Some(info) = self.edges.write().await.get_mut(&edge) {
            info.healthy = true;
            info!(edge = edge.0, "Edge marked healthy");
        }
    }

    /// Get edge count.
    pub async fn edge_count(&self) -> usize {
        self.edges.read().await.len()
    }

    /// Get healthy edge count.
    pub async fn healthy_edge_count(&self) -> usize {
        self.edges
            .read()
            .await
            .values()
            .filter(|e| e.healthy)
            .count()
    }

    /// Get GPU-capable edge count.
    pub async fn gpu_edge_count(&self) -> usize {
        self.edges
            .read()
            .await
            .values()
            .filter(|e| e.gpu_count > 0)
            .count()
    }

    /// Get placement statistics.
    pub async fn stats(&self) -> BrainLinkStats {
        let edges = self.edges.read().await;
        let links = self.links.read().await;

        let total_edges = edges.len();
        let healthy_edges = edges.values().filter(|e| e.healthy).count();
        let gpu_edges = edges.values().filter(|e| e.gpu_count > 0).count();
        let dpu_edges = edges.values().filter(|e| e.has_dpu()).count();
        let dpu_inline_edges = edges.values().filter(|e| e.has_dpu_inline()).count();
        let high_perf_edges = edges
            .values()
            .filter(|e| e.has_high_perf_transport())
            .count();

        let total_links = links.len();
        let healthy_links = links.values().filter(|l| l.healthy).count();

        let avg_load = if edges.is_empty() {
            0.0
        } else {
            edges.values().map(|e| e.load).sum::<f64>() / edges.len() as f64
        };

        BrainLinkStats {
            total_edges,
            healthy_edges,
            gpu_edges,
            dpu_edges,
            dpu_inline_edges,
            high_perf_edges,
            total_links,
            healthy_links,
            average_load: avg_load,
        }
    }

    /// Get DPU-capable edge count.
    pub async fn dpu_edge_count(&self) -> usize {
        self.edges
            .read()
            .await
            .values()
            .filter(|e| e.has_dpu())
            .count()
    }
}

impl Default for BrainLink {
    fn default() -> Self {
        Self::new()
    }
}

/// Brain-Link statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrainLinkStats {
    /// Total edges.
    pub total_edges: usize,
    /// Healthy edges.
    pub healthy_edges: usize,
    /// GPU-capable edges.
    pub gpu_edges: usize,
    /// DPU-capable edges.
    pub dpu_edges: usize,
    /// Edges with DPU inline processing.
    pub dpu_inline_edges: usize,
    /// Edges with high-performance transport.
    pub high_perf_edges: usize,
    /// Total links.
    pub total_links: usize,
    /// Healthy links.
    pub healthy_links: usize,
    /// Average edge load.
    pub average_load: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_brain_link_creation() {
        let brain = BrainLink::new();
        assert_eq!(brain.edge_count().await, 0);
    }

    #[tokio::test]
    async fn test_edge_registration() {
        let brain = BrainLink::new();

        let edge = EdgeNodeInfo::new(EdgeIdx(1), "node-1")
            .with_gpus(8, 16 * 1024 * 1024 * 1024)
            .with_transport(TransportType::Rdma);

        brain.register_edge(edge).await;

        assert_eq!(brain.edge_count().await, 1);
        assert_eq!(brain.gpu_edge_count().await, 1);
    }

    #[tokio::test]
    async fn test_placement_request() {
        let brain = BrainLink::new();

        // Register some edges
        brain
            .register_edge(
                EdgeNodeInfo::new(EdgeIdx(1), "node-1").with_gpus(4, 16 * 1024 * 1024 * 1024),
            )
            .await;
        brain
            .register_edge(
                EdgeNodeInfo::new(EdgeIdx(2), "node-2").with_gpus(8, 32 * 1024 * 1024 * 1024),
            )
            .await;

        let request = ChunkPlacementRequest {
            chunk_id: ChunkId(1),
            chunk_hash: [1u8; 32],
            chunk_size: 1024 * 1024,
            target_gpu: Some(0),
            prefer_local: true,
            pattern: CommunicationPattern::PointToPoint,
            priority: 100,
            required_transport: None,
        };

        let placement = brain.request_placement(request).await.unwrap();

        assert!(!placement.source_edges.is_empty());
        assert!(placement.score > 0.0);
    }

    #[tokio::test]
    async fn test_batch_placement() {
        let brain = BrainLink::new();

        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(1), "node-1"))
            .await;

        let requests: Vec<ChunkPlacementRequest> = (0..10)
            .map(|i| ChunkPlacementRequest {
                chunk_id: ChunkId(i as u64),
                chunk_hash: [i as u8; 32],
                chunk_size: 1024 * 1024,
                ..Default::default()
            })
            .collect();

        let placements = brain.request_batch_placement(requests).await.unwrap();
        assert_eq!(placements.len(), 10);
    }

    #[tokio::test]
    async fn test_edge_health() {
        let brain = BrainLink::new();

        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(1), "node-1"))
            .await;

        assert_eq!(brain.healthy_edge_count().await, 1);

        brain.mark_edge_unhealthy(EdgeIdx(1)).await;
        assert_eq!(brain.healthy_edge_count().await, 0);

        brain.mark_edge_healthy(EdgeIdx(1)).await;
        assert_eq!(brain.healthy_edge_count().await, 1);
    }

    #[tokio::test]
    async fn test_edge_load() {
        let brain = BrainLink::new();

        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(1), "node-1"))
            .await;

        brain.update_edge_load(EdgeIdx(1), 0.75).await;

        let stats = brain.stats().await;
        assert!((stats.average_load - 0.75).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_network_link() {
        let link = NetworkLink::new(
            EdgeIdx(1),
            EdgeIdx(2),
            vec![TransportType::Tcp, TransportType::Rdma],
        );

        assert_eq!(link.best_transport, TransportType::Rdma); // Lower latency
        assert!(link.healthy);
        assert!(link.score() > 0.0);
    }

    #[test]
    fn test_communication_pattern() {
        assert!(CommunicationPattern::AllReduce.benefits_from_locality());
        assert!(!CommunicationPattern::PointToPoint.benefits_from_locality());
        assert!(
            CommunicationPattern::AllReduce.bandwidth_factor()
                > CommunicationPattern::PointToPoint.bandwidth_factor()
        );
    }

    #[test]
    fn test_transport_type() {
        assert!(TransportType::NvLink.is_high_performance());
        assert!(TransportType::Rdma.is_high_performance());
        assert!(!TransportType::Tcp.is_high_performance());

        assert!(TransportType::NvLink.bandwidth_gbps() > TransportType::Tcp.bandwidth_gbps());
        assert!(TransportType::NvLink.latency_us() < TransportType::Tcp.latency_us());
    }

    #[test]
    fn test_edge_placement_score() {
        let edge = EdgeNodeInfo::new(EdgeIdx(1), "node-1")
            .with_gpus(8, 32 * 1024 * 1024 * 1024)
            .with_transport(TransportType::NvLink);

        let request = ChunkPlacementRequest {
            target_gpu: Some(0),
            chunk_size: 1024 * 1024,
            ..Default::default()
        };

        let score = edge.placement_score(&request);
        assert!(score > 100.0); // Bonuses for GPU and high-perf transport
    }

    #[tokio::test]
    async fn test_stats() {
        let brain = BrainLink::new();

        brain
            .register_edge(
                EdgeNodeInfo::new(EdgeIdx(1), "node-1")
                    .with_gpus(4, 16 * 1024 * 1024 * 1024)
                    .with_transport(TransportType::Rdma),
            )
            .await;
        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(2), "node-2"))
            .await;

        brain
            .add_link(NetworkLink::new(
                EdgeIdx(1),
                EdgeIdx(2),
                vec![TransportType::Tcp],
            ))
            .await;

        let stats = brain.stats().await;

        assert_eq!(stats.total_edges, 2);
        assert_eq!(stats.healthy_edges, 2);
        assert_eq!(stats.gpu_edges, 1);
        assert_eq!(stats.high_perf_edges, 1);
        assert_eq!(stats.total_links, 1);
        assert_eq!(stats.healthy_links, 1);
    }

    #[test]
    fn test_dpu_type() {
        assert!(!DpuType::None.is_hardware());
        assert!(DpuType::BlueField.is_hardware());
        assert!(DpuType::Pensando.is_hardware());
        assert!(DpuType::IntelIpu.is_hardware());
    }

    #[test]
    fn test_dpu_capabilities() {
        let caps = DpuCapabilities::bluefield3();
        assert!(caps.has_inline_crypto);
        assert!(caps.has_inline_compress);
        assert!(caps.has_inline_ec);
        assert!(caps.has_rdma);
        assert_eq!(caps.network_bandwidth_gbps, 400);
        assert_eq!(caps.generation, 3);
        assert!(caps.has_any_acceleration());
        assert!(caps.score() > 40.0); // Should have high score with all features
    }

    #[test]
    fn test_dpu_transport() {
        assert!(TransportType::DpuInline.uses_dpu());
        assert!(TransportType::DpuRdma.uses_dpu());
        assert!(!TransportType::Rdma.uses_dpu());
        assert!(!TransportType::Tcp.uses_dpu());

        assert!(TransportType::DpuInline.supports_inline_processing());
        assert!(TransportType::DpuRdma.supports_inline_processing());
        assert!(!TransportType::Rdma.supports_inline_processing());

        // DPU transports are high-performance
        assert!(TransportType::DpuInline.is_high_performance());
        assert!(TransportType::DpuRdma.is_high_performance());
    }

    #[test]
    fn test_edge_with_dpu() {
        let edge = EdgeNodeInfo::new(EdgeIdx(1), "dpu-node").with_dpu(
            2,
            DpuType::BlueField,
            DpuCapabilities::bluefield3(),
        );

        assert!(edge.has_dpu());
        assert!(edge.has_dpu_inline());
        assert_eq!(edge.dpu_count, 2);
        assert_eq!(edge.dpu_type, DpuType::BlueField);

        // Should have DPU transports auto-added
        assert!(edge.transports.contains(&TransportType::DpuRdma));
        assert!(edge.transports.contains(&TransportType::DpuInline));
    }

    #[test]
    fn test_dpu_placement_score() {
        let edge_without_dpu =
            EdgeNodeInfo::new(EdgeIdx(1), "node-1").with_transport(TransportType::Rdma);

        let edge_with_dpu = EdgeNodeInfo::new(EdgeIdx(2), "node-2").with_dpu(
            1,
            DpuType::BlueField,
            DpuCapabilities::bluefield3(),
        );

        let request = ChunkPlacementRequest {
            chunk_size: 1024 * 1024,
            ..Default::default()
        };

        let score_without = edge_without_dpu.placement_score(&request);
        let score_with = edge_with_dpu.placement_score(&request);

        // DPU edge should have higher score
        assert!(
            score_with > score_without,
            "DPU edge ({}) should score higher than non-DPU edge ({})",
            score_with,
            score_without
        );
    }

    #[test]
    fn test_dpu_transport_preference() {
        let edge = EdgeNodeInfo::new(EdgeIdx(1), "dpu-node").with_dpu(
            1,
            DpuType::BlueField,
            DpuCapabilities::bluefield3(),
        );

        // Request requiring DPU transport
        let dpu_request = ChunkPlacementRequest {
            chunk_size: 1024 * 1024,
            required_transport: Some(TransportType::DpuRdma),
            ..Default::default()
        };

        // Request requiring non-DPU transport
        let rdma_request = ChunkPlacementRequest {
            chunk_size: 1024 * 1024,
            required_transport: Some(TransportType::Rdma),
            ..Default::default()
        };

        let dpu_score = edge.placement_score(&dpu_request);
        let rdma_score = edge.placement_score(&rdma_request);

        // DPU request should score higher on DPU node (DPU bonus + required transport match)
        assert!(dpu_score > rdma_score);
    }

    #[tokio::test]
    async fn test_stats_with_dpu() {
        let brain = BrainLink::new();

        // Register edge without DPU
        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(1), "cpu-node"))
            .await;

        // Register edge with DPU
        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(2), "dpu-node").with_dpu(
                2,
                DpuType::BlueField,
                DpuCapabilities::bluefield3(),
            ))
            .await;

        let stats = brain.stats().await;

        assert_eq!(stats.total_edges, 2);
        assert_eq!(stats.dpu_edges, 1);
        assert_eq!(stats.dpu_inline_edges, 1);
        assert!(stats.high_perf_edges >= 1); // DPU edge has high-perf transport
    }

    #[tokio::test]
    async fn test_dpu_edge_count() {
        let brain = BrainLink::new();

        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(1), "cpu-node"))
            .await;
        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(2), "dpu-node-1").with_dpu(
                1,
                DpuType::BlueField,
                DpuCapabilities::bluefield3(),
            ))
            .await;
        brain
            .register_edge(EdgeNodeInfo::new(EdgeIdx(3), "dpu-node-2").with_dpu(
                2,
                DpuType::BlueField,
                DpuCapabilities::bluefield3(),
            ))
            .await;

        assert_eq!(brain.dpu_edge_count().await, 2);
        assert_eq!(brain.gpu_edge_count().await, 0);
    }
}
