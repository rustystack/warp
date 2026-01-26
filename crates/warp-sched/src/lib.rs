//! GPU-Accelerated Chunk Scheduler for Portal Distributed Storage
//!
//! This crate provides GPU-accelerated scheduling for millions of chunks
//! across thousands of edges, achieving <10ms scheduling latency for 10M
//! chunks with <50ms failover times.
//!
//! # Key Components
//!
//! - **State Buffers**: GPU-resident chunk and edge state
//! - **Cost Matrix**: Parallel computation of transfer costs
//! - **K-Best Paths**: Selection of optimal source edges
//! - **Failover Manager**: Sub-50ms failure detection and recovery
//! - **Load Balancer**: Prevent edge bottlenecks
//! - **Dispatch Queue**: CPU-readable scheduling output

pub mod backpressure;
pub mod balance;
pub mod brain_link;
pub mod constraints;
pub mod cost;
pub mod dispatch;
pub mod failover;
pub mod paths;
pub mod reoptimize;
pub mod saturation;
pub mod scheduler;
pub mod slai_integration;
pub mod state;
pub mod types;

pub use backpressure::{BackpressureConfig, BackpressureState, BackpressureSummary};
pub use balance::{
    CpuLoadBalancer, LoadBalanceConfig, LoadBalancer, LoadMetrics, RebalanceOp, RebalancePlan,
};
pub use brain_link::{
    BrainLink, BrainLinkStats, ChunkPlacement, ChunkPlacementRequest, CommunicationPattern,
    DpuCapabilities, DpuType, EdgeNodeInfo, NetworkLink, TransportType,
};
pub use slai_integration::{
    SlaiCombinedMetrics, SlaiIntegrationConfig, SlaiIntegrationStats, SlaiSchedulingIntegration,
    UnifiedPlacement, UnifiedPlacementRequest, WorkloadType as SchedWorkloadType,
};
pub use constraints::{
    ConstraintEvaluator, ConstraintViolation, CostConstraint, EdgeConstraints, PolicyEngine,
    PowerConstraint, SchedulePolicy, TimeConstraint, TimeWindow, ViolationSeverity,
};
pub use cost::{CostConfig, CostMatrix, CpuCostMatrix};
pub use dispatch::DispatchQueue;
pub use failover::{CpuFailoverManager, FailoverAction, FailoverDecision, FailoverManager};
pub use paths::{CpuPathSelector, PathConfig, PathSelection, PathSelector};
pub use reoptimize::{
    IncrementalConfig, IncrementalScheduler, Reassignment, ReassignmentReason, ReoptMetrics,
    ReoptPlan, ReoptScope, ReoptState, ReoptStrategy,
};
pub use saturation::{SaturationDetector, SaturationSummary};
pub use scheduler::{ChunkScheduler, CpuChunkScheduler, SchedulerConfig};
pub use state::{CpuStateBuffers, GpuStateBuffers, StateSnapshot};
pub use types::{
    Assignment, AssignmentBatch, ChunkId, ChunkState, ChunkStatus, DynamicEdgeMetrics, EdgeIdx,
    EdgeStateGpu, PathThroughput, RttTrend, ScheduleRequest, SchedulerMetrics,
};

use thiserror::Error;

/// Scheduler error types
#[derive(Debug, Error)]
pub enum SchedError {
    /// GPU operation failed
    #[error("GPU error: {0}")]
    Gpu(String),

    /// Edge registry error
    #[error("Edge error: {0}")]
    Edge(#[from] warp_edge::EdgeError),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Scheduler not running
    #[error("Scheduler not running")]
    NotRunning,

    /// Buffer overflow
    #[error("Buffer overflow: {0}")]
    BufferOverflow(String),

    /// Resource exhausted
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// CUDA kernel error
    #[error("CUDA kernel error: {0}")]
    Kernel(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Result type for warp-sched operations
pub type Result<T> = std::result::Result<T, SchedError>;
