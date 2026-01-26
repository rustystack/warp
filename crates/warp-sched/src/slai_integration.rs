//! SLAI PlacementEngine ↔ BrainLink Integration
//!
//! This module bridges the SLAI PlacementEngine (workload prediction, node placement)
//! with BrainLink (GPU-aware chunk placement, DPU support) to provide unified
//! intelligent scheduling across the WARP HPC stack.
//!
//! # Features
//!
//! - **Unified Placement API**: Single interface for both workload-aware and transport-aware placement
//! - **Workload-to-Transport Mapping**: Automatic transport selection based on ML workload type
//! - **Cross-System Metrics**: Aggregated statistics from both scheduling systems
//! - **DPU-Aware Decisions**: Incorporates DPU capabilities into placement decisions
//!
//! # Example
//!
//! ```ignore
//! use warp_sched::slai_integration::{SlaiSchedulingIntegration, WorkloadToTransport};
//! use warp_sched::brain_link::BrainLink;
//!
//! let brain_link = BrainLink::new();
//! let integration = SlaiSchedulingIntegration::new(brain_link);
//!
//! // Get optimal placement considering both workload and transport
//! let placement = integration.get_optimal_placement(request).await?;
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::brain_link::{
    BrainLink, BrainLinkStats, ChunkPlacement, ChunkPlacementRequest, CommunicationPattern,
    DpuCapabilities, DpuType, EdgeNodeInfo, TransportType,
};
use crate::types::{ChunkId, EdgeIdx};
use crate::{Result, SchedError};

/// Workload type from SLAI PlacementEngine
///
/// Mirrors the `WorkloadType` from `warp-store` to avoid cross-crate dependencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkloadType {
    /// ML model training (sequential batch reads)
    Training,
    /// ML inference (repeated model reads)
    Inference,
    /// Checkpoint saving (large sequential writes)
    Checkpointing,
    /// Data preprocessing (read-heavy, random)
    Preprocessing,
    /// Model evaluation (similar to inference)
    Evaluation,
    /// Data augmentation (read-modify-write)
    Augmentation,
    /// Unknown workload pattern
    Unknown,
}

impl WorkloadType {
    /// Map workload type to optimal communication pattern
    pub fn to_communication_pattern(&self) -> CommunicationPattern {
        match self {
            Self::Training => CommunicationPattern::AllGather,
            Self::Inference => CommunicationPattern::PointToPoint,
            Self::Checkpointing => CommunicationPattern::Broadcast,
            Self::Preprocessing => CommunicationPattern::Scatter,
            Self::Evaluation => CommunicationPattern::PointToPoint,
            Self::Augmentation => CommunicationPattern::Scatter,
            Self::Unknown => CommunicationPattern::PointToPoint,
        }
    }

    /// Get optimal transport type for this workload
    pub fn preferred_transport(&self) -> TransportType {
        match self {
            Self::Training => TransportType::Rdma, // High bandwidth for gradients
            Self::Inference => TransportType::NvLink, // Low latency for model access
            Self::Checkpointing => TransportType::DpuRdma, // DPU inline compression
            Self::Preprocessing => TransportType::GpuDirect, // GPU-direct for tensor loading
            Self::Evaluation => TransportType::NvLink,
            Self::Augmentation => TransportType::SharedMemory, // Local transforms
            Self::Unknown => TransportType::Tcp, // Safe default
        }
    }

    /// Check if this workload benefits from GPU placement
    pub fn benefits_from_gpu(&self) -> bool {
        matches!(
            self,
            Self::Training | Self::Inference | Self::Evaluation | Self::Preprocessing
        )
    }

    /// Check if this workload benefits from DPU inline processing
    pub fn benefits_from_dpu(&self) -> bool {
        matches!(self, Self::Checkpointing | Self::Training)
    }
}

/// Unified placement request combining SLAI and BrainLink parameters
#[derive(Debug, Clone)]
pub struct UnifiedPlacementRequest {
    /// Chunk identifier
    pub chunk_id: ChunkId,
    /// Chunk hash for deduplication/logging
    pub chunk_hash: [u8; 32],
    /// Chunk size in bytes
    pub chunk_size: u64,
    /// Detected or specified workload type
    pub workload_type: WorkloadType,
    /// Session ID for workload tracking
    pub session_id: Option<String>,
    /// Object key for SLAI tracking
    pub object_key: Option<String>,
    /// Explicit GPU target (overrides automatic selection)
    pub target_gpu: Option<u32>,
    /// Prefer local storage
    pub prefer_local: bool,
    /// Request priority (0-255)
    pub priority: u8,
    /// Force specific transport (overrides automatic selection)
    pub force_transport: Option<TransportType>,
    /// Require DPU inline processing
    pub require_dpu: bool,
}

impl Default for UnifiedPlacementRequest {
    fn default() -> Self {
        Self {
            chunk_id: ChunkId(0),
            chunk_hash: [0u8; 32],
            chunk_size: 0,
            workload_type: WorkloadType::Unknown,
            session_id: None,
            object_key: None,
            target_gpu: None,
            prefer_local: true,
            priority: 100,
            force_transport: None,
            require_dpu: false,
        }
    }
}

/// Unified placement result combining SLAI hints and BrainLink decisions
#[derive(Debug, Clone)]
pub struct UnifiedPlacement {
    /// BrainLink chunk placement
    pub chunk_placement: ChunkPlacement,
    /// Detected/specified workload type
    pub workload_type: WorkloadType,
    /// Recommended communication pattern
    pub pattern: CommunicationPattern,
    /// Selected transport type
    pub transport: TransportType,
    /// DPU capabilities available at placement
    pub dpu_available: bool,
    /// DPU inline processing recommended
    pub use_dpu_inline: bool,
    /// Prefetch suggestions from SLAI
    pub prefetch_objects: Vec<String>,
    /// Cache priority (0-100)
    pub cache_priority: u8,
    /// Combined confidence score
    pub confidence: f64,
}

/// SLAI scheduling integration coordinator
///
/// Bridges PlacementEngine and BrainLink to provide unified intelligent
/// scheduling that considers both workload patterns and transport capabilities.
pub struct SlaiSchedulingIntegration {
    /// BrainLink scheduler
    brain_link: Arc<RwLock<BrainLink>>,
    /// Workload type overrides (session_id -> WorkloadType)
    workload_overrides: RwLock<HashMap<String, WorkloadType>>,
    /// Prefetch cache (object_key -> predicted_objects)
    prefetch_cache: RwLock<HashMap<String, Vec<String>>>,
    /// Statistics
    stats: RwLock<SlaiIntegrationStats>,
    /// Configuration
    config: SlaiIntegrationConfig,
}

/// Configuration for SLAI integration
#[derive(Debug, Clone)]
pub struct SlaiIntegrationConfig {
    /// Enable automatic workload-to-transport mapping
    pub auto_transport_mapping: bool,
    /// Enable DPU preference for compatible workloads
    pub prefer_dpu: bool,
    /// Minimum chunk size for DPU offload (bytes)
    pub min_dpu_chunk_size: u64,
    /// Enable prefetch suggestions
    pub enable_prefetch: bool,
    /// Maximum prefetch suggestions per request
    pub max_prefetch_suggestions: usize,
}

impl Default for SlaiIntegrationConfig {
    fn default() -> Self {
        Self {
            auto_transport_mapping: true,
            prefer_dpu: true,
            min_dpu_chunk_size: 64 * 1024, // 64KB minimum for DPU
            enable_prefetch: true,
            max_prefetch_suggestions: 5,
        }
    }
}

/// Statistics for SLAI integration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlaiIntegrationStats {
    /// Total placement requests
    pub total_requests: u64,
    /// Placements with DPU
    pub dpu_placements: u64,
    /// Placements by workload type
    pub by_workload: HashMap<String, u64>,
    /// Placements by transport type
    pub by_transport: HashMap<String, u64>,
    /// GPU placements
    pub gpu_placements: u64,
    /// Prefetch suggestions made
    pub prefetch_suggestions: u64,
    /// Average confidence score
    pub avg_confidence: f64,
}

impl SlaiSchedulingIntegration {
    /// Create a new SLAI scheduling integration
    pub fn new(brain_link: BrainLink) -> Self {
        Self {
            brain_link: Arc::new(RwLock::new(brain_link)),
            workload_overrides: RwLock::new(HashMap::new()),
            prefetch_cache: RwLock::new(HashMap::new()),
            stats: RwLock::new(SlaiIntegrationStats::default()),
            config: SlaiIntegrationConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(brain_link: BrainLink, config: SlaiIntegrationConfig) -> Self {
        Self {
            brain_link: Arc::new(RwLock::new(brain_link)),
            workload_overrides: RwLock::new(HashMap::new()),
            prefetch_cache: RwLock::new(HashMap::new()),
            stats: RwLock::new(SlaiIntegrationStats::default()),
            config,
        }
    }

    /// Get optimal placement considering both workload and transport
    pub async fn get_optimal_placement(
        &self,
        request: UnifiedPlacementRequest,
    ) -> Result<UnifiedPlacement> {
        // Determine workload type (check overrides first)
        let workload_type = if let Some(session_id) = &request.session_id {
            self.workload_overrides
                .read()
                .await
                .get(session_id)
                .copied()
                .unwrap_or(request.workload_type)
        } else {
            request.workload_type
        };

        // Map workload to communication pattern
        let pattern = workload_type.to_communication_pattern();

        // Determine transport type
        let transport = if let Some(forced) = request.force_transport {
            forced
        } else if self.config.auto_transport_mapping {
            self.select_transport(&request, workload_type).await
        } else {
            workload_type.preferred_transport()
        };

        // Build BrainLink placement request
        let brain_link_request = ChunkPlacementRequest {
            chunk_id: request.chunk_id,
            chunk_hash: request.chunk_hash,
            chunk_size: request.chunk_size,
            target_gpu: if workload_type.benefits_from_gpu() {
                request.target_gpu.or(Some(0))
            } else {
                request.target_gpu
            },
            prefer_local: request.prefer_local,
            pattern,
            priority: request.priority,
            required_transport: if request.require_dpu {
                Some(TransportType::DpuRdma)
            } else {
                Some(transport)
            },
        };

        // Get placement from BrainLink
        let brain_link = self.brain_link.read().await;
        let chunk_placement = brain_link.request_placement(brain_link_request).await?;

        // Check DPU availability
        let dpu_available = self.check_dpu_availability(&brain_link, &chunk_placement).await;
        let use_dpu_inline = dpu_available
            && self.config.prefer_dpu
            && workload_type.benefits_from_dpu()
            && request.chunk_size >= self.config.min_dpu_chunk_size;

        // Get prefetch suggestions
        let prefetch_objects = if self.config.enable_prefetch {
            self.get_prefetch_suggestions(&request).await
        } else {
            Vec::new()
        };

        // Calculate cache priority based on workload
        let cache_priority = self.calculate_cache_priority(workload_type);

        // Calculate confidence score
        let confidence = chunk_placement.score / 200.0; // Normalize to 0-1

        // Update statistics
        self.update_stats(
            workload_type,
            transport,
            chunk_placement.target_gpu.is_some(),
            dpu_available,
            prefetch_objects.len(),
            confidence,
        )
        .await;

        debug!(
            chunk_id = chunk_placement.chunk_id.0,
            workload = ?workload_type,
            transport = ?transport,
            dpu = use_dpu_inline,
            confidence,
            "Unified placement decision"
        );

        Ok(UnifiedPlacement {
            chunk_placement,
            workload_type,
            pattern,
            transport,
            dpu_available,
            use_dpu_inline,
            prefetch_objects,
            cache_priority,
            confidence,
        })
    }

    /// Select optimal transport based on workload and available capabilities
    async fn select_transport(
        &self,
        request: &UnifiedPlacementRequest,
        workload_type: WorkloadType,
    ) -> TransportType {
        let preferred = workload_type.preferred_transport();

        // Check if DPU is preferred and available
        if self.config.prefer_dpu
            && workload_type.benefits_from_dpu()
            && request.chunk_size >= self.config.min_dpu_chunk_size
        {
            let brain_link = self.brain_link.read().await;
            if brain_link.dpu_edge_count().await > 0 {
                return TransportType::DpuRdma;
            }
        }

        // Check if GPU-direct is preferred and available
        if workload_type.benefits_from_gpu() && request.target_gpu.is_some() {
            let brain_link = self.brain_link.read().await;
            if brain_link.gpu_edge_count().await > 0 {
                return TransportType::GpuDirect;
            }
        }

        preferred
    }

    /// Check if DPU is available at the placement location
    async fn check_dpu_availability(
        &self,
        brain_link: &BrainLink,
        placement: &ChunkPlacement,
    ) -> bool {
        brain_link.dpu_edge_count().await > 0
            && placement.transport.uses_dpu()
    }

    /// Get prefetch suggestions based on object key
    async fn get_prefetch_suggestions(&self, request: &UnifiedPlacementRequest) -> Vec<String> {
        if let Some(object_key) = &request.object_key {
            // Check cache first
            if let Some(cached) = self.prefetch_cache.read().await.get(object_key) {
                return cached
                    .iter()
                    .take(self.config.max_prefetch_suggestions)
                    .cloned()
                    .collect();
            }

            // Generate simple prefetch suggestions based on naming patterns
            let suggestions = self.generate_prefetch_suggestions(object_key);

            // Cache the suggestions
            if !suggestions.is_empty() {
                self.prefetch_cache
                    .write()
                    .await
                    .insert(object_key.clone(), suggestions.clone());
            }

            suggestions
        } else {
            Vec::new()
        }
    }

    /// Generate prefetch suggestions based on object naming patterns
    fn generate_prefetch_suggestions(&self, object_key: &str) -> Vec<String> {
        let mut suggestions = Vec::new();

        // Detect batch pattern (e.g., batch_0.bin, batch_1.bin, ...)
        if let Some(pos) = object_key.rfind('_') {
            let prefix = &object_key[..pos + 1];
            let suffix = &object_key[pos + 1..];

            // Try to parse as number
            if let Some(dot_pos) = suffix.find('.') {
                let num_part = &suffix[..dot_pos];
                let ext = &suffix[dot_pos..];

                if let Ok(num) = num_part.parse::<u64>() {
                    // Suggest next N items in sequence
                    for i in 1..=self.config.max_prefetch_suggestions {
                        suggestions.push(format!("{}{}{}", prefix, num + i as u64, ext));
                    }
                }
            }
        }

        suggestions
    }

    /// Calculate cache priority based on workload type
    fn calculate_cache_priority(&self, workload_type: WorkloadType) -> u8 {
        match workload_type {
            WorkloadType::Inference => 95, // Highest - model weights
            WorkloadType::Training => 80,
            WorkloadType::Evaluation => 70,
            WorkloadType::Checkpointing => 60,
            WorkloadType::Preprocessing => 40,
            WorkloadType::Augmentation => 30,
            WorkloadType::Unknown => 50,
        }
    }

    /// Update statistics
    async fn update_stats(
        &self,
        workload_type: WorkloadType,
        transport: TransportType,
        is_gpu: bool,
        is_dpu: bool,
        prefetch_count: usize,
        confidence: f64,
    ) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;

        if is_dpu {
            stats.dpu_placements += 1;
        }
        if is_gpu {
            stats.gpu_placements += 1;
        }
        if prefetch_count > 0 {
            stats.prefetch_suggestions += prefetch_count as u64;
        }

        // Update by-workload counts
        let workload_key = format!("{:?}", workload_type);
        *stats.by_workload.entry(workload_key).or_insert(0) += 1;

        // Update by-transport counts
        let transport_key = format!("{:?}", transport);
        *stats.by_transport.entry(transport_key).or_insert(0) += 1;

        // Update average confidence
        let total = stats.avg_confidence * (stats.total_requests - 1) as f64 + confidence;
        stats.avg_confidence = total / stats.total_requests as f64;
    }

    /// Register a workload type override for a session
    pub async fn register_workload(&self, session_id: &str, workload_type: WorkloadType) {
        self.workload_overrides
            .write()
            .await
            .insert(session_id.to_string(), workload_type);
        info!(session_id, workload = ?workload_type, "Registered workload override");
    }

    /// Unregister a workload override
    pub async fn unregister_workload(&self, session_id: &str) {
        self.workload_overrides.write().await.remove(session_id);
    }

    /// Update prefetch cache for an object
    pub async fn update_prefetch_cache(&self, object_key: &str, predictions: Vec<String>) {
        self.prefetch_cache
            .write()
            .await
            .insert(object_key.to_string(), predictions);
    }

    /// Clear prefetch cache
    pub async fn clear_prefetch_cache(&self) {
        self.prefetch_cache.write().await.clear();
    }

    /// Get integration statistics
    pub async fn stats(&self) -> SlaiIntegrationStats {
        self.stats.read().await.clone()
    }

    /// Get BrainLink statistics
    pub async fn brain_link_stats(&self) -> BrainLinkStats {
        self.brain_link.read().await.stats().await
    }

    /// Get combined metrics from all systems
    pub async fn combined_metrics(&self) -> SlaiCombinedMetrics {
        let integration_stats = self.stats.read().await.clone();
        let brain_link_stats = self.brain_link.read().await.stats().await;

        SlaiCombinedMetrics {
            integration: integration_stats,
            brain_link: brain_link_stats,
        }
    }

    /// Register an edge node with the underlying BrainLink
    pub async fn register_edge(&self, info: EdgeNodeInfo) {
        self.brain_link.write().await.register_edge(info).await;
    }

    /// Unregister an edge node
    pub async fn unregister_edge(&self, edge: EdgeIdx) {
        self.brain_link.write().await.unregister_edge(edge).await;
    }

    /// Update edge load
    pub async fn update_edge_load(&self, edge: EdgeIdx, load: f64) {
        self.brain_link.write().await.update_edge_load(edge, load).await;
    }

    /// Get the configuration
    pub fn config(&self) -> &SlaiIntegrationConfig {
        &self.config
    }
}

/// Combined metrics from SLAI integration and BrainLink
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaiCombinedMetrics {
    /// SLAI integration statistics
    pub integration: SlaiIntegrationStats,
    /// BrainLink statistics
    pub brain_link: BrainLinkStats,
}

impl SlaiCombinedMetrics {
    /// Get total placement requests
    pub fn total_requests(&self) -> u64 {
        self.integration.total_requests
    }

    /// Get DPU utilization percentage
    pub fn dpu_utilization(&self) -> f64 {
        if self.integration.total_requests == 0 {
            return 0.0;
        }
        self.integration.dpu_placements as f64 / self.integration.total_requests as f64 * 100.0
    }

    /// Get GPU utilization percentage
    pub fn gpu_utilization(&self) -> f64 {
        if self.integration.total_requests == 0 {
            return 0.0;
        }
        self.integration.gpu_placements as f64 / self.integration.total_requests as f64 * 100.0
    }

    /// Get high-performance transport percentage
    pub fn high_perf_transport_percentage(&self) -> f64 {
        if self.integration.total_requests == 0 {
            return 0.0;
        }

        let high_perf_count: u64 = self
            .integration
            .by_transport
            .iter()
            .filter(|(k, _)| {
                k.contains("Rdma")
                    || k.contains("NvLink")
                    || k.contains("InfiniBand")
                    || k.contains("Dpu")
                    || k.contains("GpuDirect")
            })
            .map(|(_, v)| v)
            .sum();

        high_perf_count as f64 / self.integration.total_requests as f64 * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workload_to_pattern() {
        assert_eq!(
            WorkloadType::Training.to_communication_pattern(),
            CommunicationPattern::AllGather
        );
        assert_eq!(
            WorkloadType::Inference.to_communication_pattern(),
            CommunicationPattern::PointToPoint
        );
        assert_eq!(
            WorkloadType::Checkpointing.to_communication_pattern(),
            CommunicationPattern::Broadcast
        );
    }

    #[test]
    fn test_workload_transport_preference() {
        assert_eq!(
            WorkloadType::Training.preferred_transport(),
            TransportType::Rdma
        );
        assert_eq!(
            WorkloadType::Inference.preferred_transport(),
            TransportType::NvLink
        );
        assert_eq!(
            WorkloadType::Checkpointing.preferred_transport(),
            TransportType::DpuRdma
        );
    }

    #[test]
    fn test_workload_gpu_benefits() {
        assert!(WorkloadType::Training.benefits_from_gpu());
        assert!(WorkloadType::Inference.benefits_from_gpu());
        assert!(!WorkloadType::Augmentation.benefits_from_gpu());
    }

    #[test]
    fn test_workload_dpu_benefits() {
        assert!(WorkloadType::Checkpointing.benefits_from_dpu());
        assert!(WorkloadType::Training.benefits_from_dpu());
        assert!(!WorkloadType::Inference.benefits_from_dpu());
    }

    #[tokio::test]
    async fn test_integration_creation() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        let stats = integration.stats().await;
        assert_eq!(stats.total_requests, 0);
    }

    #[tokio::test]
    async fn test_workload_override() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        integration
            .register_workload("session-1", WorkloadType::Training)
            .await;

        let overrides = integration.workload_overrides.read().await;
        assert_eq!(overrides.get("session-1"), Some(&WorkloadType::Training));
    }

    #[test]
    fn test_prefetch_suggestions() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        let suggestions = integration.generate_prefetch_suggestions("batch_0.bin");
        assert!(!suggestions.is_empty());
        assert!(suggestions.contains(&"batch_1.bin".to_string()));
    }

    #[test]
    fn test_cache_priority() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        assert!(
            integration.calculate_cache_priority(WorkloadType::Inference)
                > integration.calculate_cache_priority(WorkloadType::Preprocessing)
        );
    }

    #[tokio::test]
    async fn test_combined_metrics() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        let metrics = integration.combined_metrics().await;
        assert_eq!(metrics.total_requests(), 0);
        assert_eq!(metrics.dpu_utilization(), 0.0);
    }

    #[test]
    fn test_unified_request_default() {
        let request = UnifiedPlacementRequest::default();
        assert_eq!(request.workload_type, WorkloadType::Unknown);
        assert!(request.prefer_local);
        assert_eq!(request.priority, 100);
    }

    #[test]
    fn test_config_default() {
        let config = SlaiIntegrationConfig::default();
        assert!(config.auto_transport_mapping);
        assert!(config.prefer_dpu);
        assert!(config.enable_prefetch);
    }

    #[tokio::test]
    async fn test_get_optimal_placement() {
        let brain_link = BrainLink::new();

        // Register an edge
        brain_link
            .register_edge(EdgeNodeInfo::new(EdgeIdx(1), "test-node"))
            .await;

        let integration = SlaiSchedulingIntegration::new(brain_link);

        let request = UnifiedPlacementRequest {
            chunk_id: ChunkId(1),
            chunk_hash: [0u8; 32],
            chunk_size: 1024 * 1024,
            workload_type: WorkloadType::Training,
            session_id: Some("session-1".to_string()),
            object_key: Some("batch_0.bin".to_string()),
            target_gpu: None,
            prefer_local: true,
            priority: 100,
            force_transport: None,
            require_dpu: false,
        };

        let placement = integration.get_optimal_placement(request).await.unwrap();

        assert_eq!(placement.workload_type, WorkloadType::Training);
        assert_eq!(placement.pattern, CommunicationPattern::AllGather);
        assert!(placement.confidence >= 0.0 && placement.confidence <= 1.0);
    }

    #[tokio::test]
    async fn test_register_unregister_edge() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        // Register edge
        integration
            .register_edge(EdgeNodeInfo::new(EdgeIdx(1), "test-edge"))
            .await;

        let stats = integration.brain_link_stats().await;
        assert_eq!(stats.total_edges, 1);

        // Unregister edge
        integration.unregister_edge(EdgeIdx(1)).await;

        let stats = integration.brain_link_stats().await;
        assert_eq!(stats.total_edges, 0);
    }

    #[tokio::test]
    async fn test_update_edge_load() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        integration
            .register_edge(EdgeNodeInfo::new(EdgeIdx(1), "test-edge"))
            .await;

        integration.update_edge_load(EdgeIdx(1), 0.75).await;

        let stats = integration.brain_link_stats().await;
        assert!((stats.average_load - 0.75).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_prefetch_cache() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        integration
            .update_prefetch_cache("test-key", vec!["predicted-1".to_string(), "predicted-2".to_string()])
            .await;

        let cache = integration.prefetch_cache.read().await;
        assert_eq!(cache.get("test-key").unwrap().len(), 2);
        drop(cache);

        integration.clear_prefetch_cache().await;

        let cache = integration.prefetch_cache.read().await;
        assert!(cache.is_empty());
    }

    #[test]
    fn test_combined_metrics_calculations() {
        let mut integration_stats = SlaiIntegrationStats::default();
        integration_stats.total_requests = 100;
        integration_stats.dpu_placements = 25;
        integration_stats.gpu_placements = 50;

        let metrics = SlaiCombinedMetrics {
            integration: integration_stats,
            brain_link: BrainLinkStats::default(),
        };

        assert_eq!(metrics.total_requests(), 100);
        assert!((metrics.dpu_utilization() - 25.0).abs() < 0.01);
        assert!((metrics.gpu_utilization() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_workload_type_all_variants() {
        let workloads = [
            WorkloadType::Training,
            WorkloadType::Inference,
            WorkloadType::Checkpointing,
            WorkloadType::Preprocessing,
            WorkloadType::Evaluation,
            WorkloadType::Augmentation,
            WorkloadType::Unknown,
        ];

        for workload in &workloads {
            // Each workload should have a valid pattern
            let _ = workload.to_communication_pattern();
            // Each workload should have a valid transport
            let _ = workload.preferred_transport();
            // Can check GPU benefits
            let _ = workload.benefits_from_gpu();
            // Can check DPU benefits
            let _ = workload.benefits_from_dpu();
        }
    }

    #[tokio::test]
    async fn test_with_config() {
        let brain_link = BrainLink::new();
        let config = SlaiIntegrationConfig {
            auto_transport_mapping: false,
            prefer_dpu: false,
            min_dpu_chunk_size: 128 * 1024,
            enable_prefetch: false,
            max_prefetch_suggestions: 3,
        };

        let integration = SlaiSchedulingIntegration::with_config(brain_link, config);

        assert!(!integration.config().auto_transport_mapping);
        assert!(!integration.config().prefer_dpu);
        assert!(!integration.config().enable_prefetch);
    }

    #[tokio::test]
    async fn test_unregister_workload() {
        let brain_link = BrainLink::new();
        let integration = SlaiSchedulingIntegration::new(brain_link);

        integration
            .register_workload("session-1", WorkloadType::Training)
            .await;

        {
            let overrides = integration.workload_overrides.read().await;
            assert!(overrides.contains_key("session-1"));
        }

        integration.unregister_workload("session-1").await;

        {
            let overrides = integration.workload_overrides.read().await;
            assert!(!overrides.contains_key("session-1"));
        }
    }
}
