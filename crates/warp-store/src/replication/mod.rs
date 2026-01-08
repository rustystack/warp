//! Replication policies for distributed storage
//!
//! This module provides per-bucket replication policies with:
//! - Erasure coding configuration (RS(k,m))
//! - Domain placement constraints
//! - Read preference optimization (geo-reads)
//! - Write quorum requirements

mod domain;
mod geo_router;
mod shards;
mod wireguard;

pub use domain::{Domain, DomainHealth, DomainId, DomainRegistry, NodeInfo, NodeStatus};
pub use geo_router::{GeoRouter, GeoRouterStats, LatencyStats, ShardReadPlan};
pub use shards::{
    DistributedShardManager, RemoteShardClient, ShardDistributionInfo, ShardHealth, ShardIndex,
    ShardKey, ShardLocation, ShardManagerStats, ShardVerification, TcpShardClient,
};
pub use wireguard::{
    TunnelStats, TunnelStatus, WireGuardConfig, WireGuardKeyPair, WireGuardTunnel,
    WireGuardTunnelManager,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-bucket replication policy
///
/// Defines how data is replicated across domains for both
/// disaster recovery and geo-optimized reads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    /// Erasure coding configuration
    pub erasure: ErasurePolicy,

    /// Domain placement constraints
    pub placement: PlacementConstraints,

    /// Read preference for geo-optimization
    pub read_preference: ReadPreference,

    /// Minimum acknowledgments before write succeeds
    pub write_quorum: usize,

    /// Enable automatic repair of degraded shards
    pub auto_repair: bool,

    /// Repair check interval in seconds
    pub repair_interval_secs: u64,
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        Self {
            erasure: ErasurePolicy::default(),
            placement: PlacementConstraints::default(),
            read_preference: ReadPreference::Nearest,
            write_quorum: 1, // At least one domain must ack
            auto_repair: true,
            repair_interval_secs: 3600, // Check every hour
        }
    }
}

impl ReplicationPolicy {
    /// Create a policy for maximum fault tolerance
    ///
    /// Uses RS(10,4) with shards spread across domains
    pub fn high_durability() -> Self {
        Self {
            erasure: ErasurePolicy {
                data_shards: 10,
                parity_shards: 4,
                distribution: ShardDistribution::SpreadDomains,
            },
            placement: PlacementConstraints {
                min_domain_spread: 3,
                ..Default::default()
            },
            write_quorum: 3, // Wait for 3 domains
            ..Default::default()
        }
    }

    /// Create a policy for low-latency access
    ///
    /// Keeps data within local domain with minimal erasure coding
    pub fn low_latency() -> Self {
        Self {
            erasure: ErasurePolicy {
                data_shards: 4,
                parity_shards: 2,
                distribution: ShardDistribution::LocalDomain,
            },
            placement: PlacementConstraints {
                min_domain_spread: 1,
                ..Default::default()
            },
            write_quorum: 1,
            read_preference: ReadPreference::Primary,
            ..Default::default()
        }
    }

    /// Total number of shards (data + parity)
    pub fn total_shards(&self) -> usize {
        self.erasure.data_shards + self.erasure.parity_shards
    }

    /// Check if policy requires cross-domain replication
    pub fn requires_cross_domain(&self) -> bool {
        matches!(self.erasure.distribution, ShardDistribution::SpreadDomains)
            || self.placement.min_domain_spread > 1
    }
}

/// Erasure coding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasurePolicy {
    /// Number of data shards (k in RS(k,m))
    pub data_shards: usize,

    /// Number of parity shards (m in RS(k,m))
    pub parity_shards: usize,

    /// How to distribute shards across domains
    pub distribution: ShardDistribution,
}

impl Default for ErasurePolicy {
    fn default() -> Self {
        Self {
            data_shards: 10,
            parity_shards: 4,
            distribution: ShardDistribution::SpreadDomains,
        }
    }
}

impl ErasurePolicy {
    /// Create RS(4,2) - 50% overhead, tolerates 2 failures
    pub fn rs_4_2() -> Self {
        Self {
            data_shards: 4,
            parity_shards: 2,
            distribution: ShardDistribution::SpreadDomains,
        }
    }

    /// Create RS(6,3) - 50% overhead, tolerates 3 failures
    pub fn rs_6_3() -> Self {
        Self {
            data_shards: 6,
            parity_shards: 3,
            distribution: ShardDistribution::SpreadDomains,
        }
    }

    /// Create RS(10,4) - 40% overhead, tolerates 4 failures (default)
    pub fn rs_10_4() -> Self {
        Self::default()
    }

    /// Create RS(16,4) - 25% overhead, tolerates 4 failures
    pub fn rs_16_4() -> Self {
        Self {
            data_shards: 16,
            parity_shards: 4,
            distribution: ShardDistribution::SpreadDomains,
        }
    }

    /// Calculate storage overhead ratio
    pub fn overhead_ratio(&self) -> f64 {
        self.parity_shards as f64 / self.data_shards as f64
    }

    /// Maximum number of failures that can be tolerated
    pub fn fault_tolerance(&self) -> usize {
        self.parity_shards
    }
}

/// How shards are distributed across domains
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ShardDistribution {
    /// Spread shards across as many domains as possible (max fault tolerance)
    #[default]
    SpreadDomains,

    /// Keep all shards within the local domain (low latency)
    LocalDomain,

    /// Custom mapping of shard index to domain ID
    Custom(HashMap<u16, DomainId>),
}

/// Domain placement constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementConstraints {
    /// Minimum number of different domains to spread shards across
    pub min_domain_spread: usize,

    /// Required domains (shards MUST be placed here)
    pub required_domains: Vec<DomainId>,

    /// Excluded domains (shards MUST NOT be placed here)
    pub excluded_domains: Vec<DomainId>,

    /// Preferred domains (try these first, but not required)
    pub preferred_domains: Vec<DomainId>,

    /// Primary domain for writes (leader for this bucket)
    pub primary_domain: Option<DomainId>,
}

impl Default for PlacementConstraints {
    fn default() -> Self {
        Self {
            min_domain_spread: 1,
            required_domains: Vec::new(),
            excluded_domains: Vec::new(),
            preferred_domains: Vec::new(),
            primary_domain: None,
        }
    }
}

impl PlacementConstraints {
    /// Check if a domain is allowed for placement
    pub fn is_domain_allowed(&self, domain_id: DomainId) -> bool {
        !self.excluded_domains.contains(&domain_id)
    }

    /// Check if a domain is required
    pub fn is_domain_required(&self, domain_id: DomainId) -> bool {
        self.required_domains.contains(&domain_id)
    }

    /// Check if a domain is preferred
    pub fn is_domain_preferred(&self, domain_id: DomainId) -> bool {
        self.preferred_domains.contains(&domain_id)
    }
}

/// Read preference for geo-optimization
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ReadPreference {
    /// Read from the geographically nearest domain
    #[default]
    Nearest,

    /// Always read from the primary domain
    Primary,

    /// Read from any available domain (fastest response wins)
    Any,

    /// Round-robin across all domains with available shards
    RoundRobin,
}

/// Write acknowledgment configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteQuorumConfig {
    /// Minimum domains that must acknowledge the write
    pub min_acks: usize,

    /// Timeout for waiting for acks (milliseconds)
    pub timeout_ms: u64,

    /// Whether to wait for primary domain specifically
    pub require_primary: bool,
}

impl Default for WriteQuorumConfig {
    fn default() -> Self {
        Self {
            min_acks: 1,
            timeout_ms: 5000,
            require_primary: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = ReplicationPolicy::default();
        assert_eq!(policy.erasure.data_shards, 10);
        assert_eq!(policy.erasure.parity_shards, 4);
        assert_eq!(policy.total_shards(), 14);
        assert!(policy.requires_cross_domain());
    }

    #[test]
    fn test_high_durability_policy() {
        let policy = ReplicationPolicy::high_durability();
        assert_eq!(policy.write_quorum, 3);
        assert_eq!(policy.placement.min_domain_spread, 3);
        assert!(policy.auto_repair);
    }

    #[test]
    fn test_low_latency_policy() {
        let policy = ReplicationPolicy::low_latency();
        assert_eq!(policy.erasure.data_shards, 4);
        assert_eq!(policy.erasure.parity_shards, 2);
        assert!(!policy.requires_cross_domain());
        assert_eq!(policy.read_preference, ReadPreference::Primary);
    }

    #[test]
    fn test_erasure_presets() {
        let rs_4_2 = ErasurePolicy::rs_4_2();
        assert_eq!(rs_4_2.fault_tolerance(), 2);
        assert!((rs_4_2.overhead_ratio() - 0.5).abs() < f64::EPSILON);

        let rs_10_4 = ErasurePolicy::rs_10_4();
        assert_eq!(rs_10_4.fault_tolerance(), 4);
        assert!((rs_10_4.overhead_ratio() - 0.4).abs() < f64::EPSILON);

        let rs_16_4 = ErasurePolicy::rs_16_4();
        assert_eq!(rs_16_4.fault_tolerance(), 4);
        assert!((rs_16_4.overhead_ratio() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_placement_constraints() {
        let mut constraints = PlacementConstraints::default();
        constraints.excluded_domains.push(1);
        constraints.required_domains.push(2);
        constraints.preferred_domains.push(3);

        assert!(!constraints.is_domain_allowed(1));
        assert!(constraints.is_domain_allowed(2));
        assert!(constraints.is_domain_required(2));
        assert!(!constraints.is_domain_required(3));
        assert!(constraints.is_domain_preferred(3));
    }
}
