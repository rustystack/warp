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

#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::float_cmp)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::single_match_else)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::redundant_else)]
#![allow(clippy::use_self)]
#![allow(clippy::unused_async)]
#![allow(clippy::semicolon_if_nothing_returned)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(dead_code)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::identity_op)]
#![allow(clippy::let_and_return)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(unsafe_code)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::range_plus_one)]
#![allow(clippy::suboptimal_flops)]
#![allow(clippy::pub_underscore_fields)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::manual_midpoint)]
#![allow(unused_must_use)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::manual_range_contains)]
#![allow(unused_comparisons)]

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
pub use slai_integration::{
    SlaiCombinedMetrics, SlaiIntegrationConfig, SlaiIntegrationStats, SlaiSchedulingIntegration,
    UnifiedPlacement, UnifiedPlacementRequest, WorkloadType as SchedWorkloadType,
};
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
