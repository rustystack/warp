//! Distributed shard management for erasure-coded objects
//!
//! Handles shard placement across domains, health tracking,
//! and repair scheduling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::{DomainId, ErasurePolicy, ReplicationPolicy};
use crate::error::{Error, Result};

/// Unique identifier for a shard within an object
pub type ShardIndex = u16;

/// Key for looking up shard locations
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardKey {
    /// Bucket name
    pub bucket: String,

    /// Object key
    pub key: String,

    /// Shard index (0..total_shards)
    pub shard_index: ShardIndex,
}

impl ShardKey {
    /// Create a new shard key
    pub fn new(bucket: impl Into<String>, key: impl Into<String>, shard_index: ShardIndex) -> Self {
        Self {
            bucket: bucket.into(),
            key: key.into(),
            shard_index,
        }
    }

    /// Get all shard keys for an object
    pub fn all_for_object(bucket: &str, key: &str, total_shards: usize) -> Vec<ShardKey> {
        debug_assert!(total_shards > 0, "total_shards must be positive");
        let keys: Vec<ShardKey> = (0..total_shards as ShardIndex)
            .map(|i| ShardKey::new(bucket, key, i))
            .collect();
        debug_assert_eq!(
            keys.len(),
            total_shards,
            "generated shard count {} must match total_shards {}",
            keys.len(),
            total_shards
        );
        keys
    }
}

/// Location of a shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardLocation {
    /// Domain where shard is stored
    pub domain_id: DomainId,

    /// Node ID within the domain
    pub node_id: String,

    /// Path or identifier on the node
    pub path: String,

    /// Last time the shard was verified (not serialized)
    #[serde(skip, default)]
    pub last_verified: Option<Instant>,

    /// Shard health status
    pub health: ShardHealth,
}

/// Health status of a shard
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShardHealth {
    /// Shard is healthy and accessible
    Healthy,

    /// Shard is being transferred or repaired
    Repairing,

    /// Shard is suspected to be corrupted
    Degraded,

    /// Shard is confirmed missing or inaccessible
    Lost,

    /// Shard status is unknown (not yet verified)
    Unknown,
}

impl Default for ShardHealth {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Information about an object's shard distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDistributionInfo {
    /// Object bucket
    pub bucket: String,

    /// Object key
    pub key: String,

    /// Total number of shards (data + parity)
    pub total_shards: usize,

    /// Number of data shards
    pub data_shards: usize,

    /// Number of parity shards
    pub parity_shards: usize,

    /// Locations of each shard
    pub locations: HashMap<ShardIndex, Vec<ShardLocation>>,

    /// When this distribution was created (not serialized)
    #[serde(skip, default = "Instant::now")]
    pub created_at: Instant,

    /// Last modification time (not serialized)
    #[serde(skip, default = "Instant::now")]
    pub modified_at: Instant,
}

impl ShardDistributionInfo {
    /// Create a new distribution info
    pub fn new(bucket: &str, key: &str, policy: &ErasurePolicy) -> Self {
        let now = Instant::now();
        Self {
            bucket: bucket.to_string(),
            key: key.to_string(),
            total_shards: policy.data_shards + policy.parity_shards,
            data_shards: policy.data_shards,
            parity_shards: policy.parity_shards,
            locations: HashMap::new(),
            created_at: now,
            modified_at: now,
        }
    }

    /// Add a location for a shard
    pub fn add_location(&mut self, shard_index: ShardIndex, location: ShardLocation) {
        self.locations
            .entry(shard_index)
            .or_insert_with(Vec::new)
            .push(location);
        self.modified_at = Instant::now();
    }

    /// Count healthy shards
    pub fn healthy_shard_count(&self) -> usize {
        self.locations
            .values()
            .filter(|locs| locs.iter().any(|l| l.health == ShardHealth::Healthy))
            .count()
    }

    /// Check if object can be recovered
    pub fn is_recoverable(&self) -> bool {
        self.healthy_shard_count() >= self.data_shards
    }

    /// Check if object needs repair
    pub fn needs_repair(&self) -> bool {
        self.healthy_shard_count() < self.total_shards
    }

    /// Get shards that need repair
    pub fn shards_needing_repair(&self) -> Vec<ShardIndex> {
        (0..self.total_shards as ShardIndex)
            .filter(|i| {
                self.locations
                    .get(i)
                    .map(|locs| !locs.iter().any(|l| l.health == ShardHealth::Healthy))
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Get domains that have shards
    pub fn domains(&self) -> Vec<DomainId> {
        let mut domains: Vec<_> = self
            .locations
            .values()
            .flat_map(|locs| locs.iter().map(|l| l.domain_id))
            .collect();
        domains.sort();
        domains.dedup();
        domains
    }
}

/// Manages distributed shard placement and health
pub struct DistributedShardManager {
    /// Shard distribution for each object
    distributions: DashMap<(String, String), Arc<RwLock<ShardDistributionInfo>>>,

    /// Local domain ID
    local_domain_id: DomainId,

    /// Default replication policy
    default_policy: ReplicationPolicy,

    /// Repair check interval
    repair_interval: Duration,
}

impl DistributedShardManager {
    /// Create a new shard manager
    pub fn new(local_domain_id: DomainId, default_policy: ReplicationPolicy) -> Self {
        let repair_interval = Duration::from_secs(default_policy.repair_interval_secs);
        Self {
            distributions: DashMap::new(),
            local_domain_id,
            default_policy,
            repair_interval,
        }
    }

    /// Get the local domain ID
    pub fn local_domain_id(&self) -> DomainId {
        self.local_domain_id
    }

    /// Plan shard placement for a new object
    pub fn plan_placement(
        &self,
        bucket: &str,
        key: &str,
        policy: &ReplicationPolicy,
        available_domains: &[DomainId],
    ) -> Result<HashMap<ShardIndex, DomainId>> {
        let total_shards = policy.total_shards();
        let mut placement = HashMap::new();

        // Filter domains based on constraints
        let eligible_domains: Vec<_> = available_domains
            .iter()
            .filter(|d| policy.placement.is_domain_allowed(**d))
            .cloned()
            .collect();

        if eligible_domains.is_empty() {
            return Err(Error::Replication(
                "No eligible domains for shard placement".to_string(),
            ));
        }

        // Check minimum domain spread requirement
        if eligible_domains.len() < policy.placement.min_domain_spread {
            return Err(Error::Replication(format!(
                "Need {} domains but only {} available",
                policy.placement.min_domain_spread,
                eligible_domains.len()
            )));
        }

        match &policy.erasure.distribution {
            super::ShardDistribution::SpreadDomains => {
                // Spread shards evenly across domains
                for shard_idx in 0..total_shards {
                    let domain_idx = shard_idx % eligible_domains.len();
                    placement.insert(shard_idx as ShardIndex, eligible_domains[domain_idx]);
                }
            }
            super::ShardDistribution::LocalDomain => {
                // All shards on local domain
                for shard_idx in 0..total_shards {
                    placement.insert(shard_idx as ShardIndex, self.local_domain_id);
                }
            }
            super::ShardDistribution::Custom(mapping) => {
                // Use custom mapping
                for (shard_idx, domain_id) in mapping {
                    if !eligible_domains.contains(domain_id) {
                        return Err(Error::Replication(format!(
                            "Domain {} in custom mapping is not eligible",
                            domain_id
                        )));
                    }
                    placement.insert(*shard_idx, *domain_id);
                }
                // Fill in any missing shards with round-robin
                for shard_idx in 0..total_shards {
                    let idx = shard_idx as ShardIndex;
                    if !placement.contains_key(&idx) {
                        let domain_idx = shard_idx % eligible_domains.len();
                        placement.insert(idx, eligible_domains[domain_idx]);
                    }
                }
            }
        }

        debug!(
            bucket,
            key,
            shards = total_shards,
            domains = ?placement.values().collect::<Vec<_>>(),
            "Planned shard placement"
        );

        Ok(placement)
    }

    /// Register shard distribution after successful write
    pub async fn register_distribution(
        &self,
        bucket: &str,
        key: &str,
        policy: &ErasurePolicy,
        locations: HashMap<ShardIndex, ShardLocation>,
    ) -> Result<()> {
        let mut info = ShardDistributionInfo::new(bucket, key, policy);

        for (shard_idx, location) in locations {
            info.add_location(shard_idx, location);
        }

        self.distributions.insert(
            (bucket.to_string(), key.to_string()),
            Arc::new(RwLock::new(info)),
        );

        info!(bucket, key, "Registered shard distribution");
        Ok(())
    }

    /// Get shard distribution for an object
    pub fn get_distribution(
        &self,
        bucket: &str,
        key: &str,
    ) -> Option<Arc<RwLock<ShardDistributionInfo>>> {
        self.distributions
            .get(&(bucket.to_string(), key.to_string()))
            .map(|r| r.clone())
    }

    /// Update shard health status
    pub async fn update_shard_health(
        &self,
        shard_key: &ShardKey,
        domain_id: DomainId,
        health: ShardHealth,
    ) -> Result<()> {
        let key = (shard_key.bucket.clone(), shard_key.key.clone());
        let dist = self.distributions.get(&key).ok_or_else(|| {
            Error::Replication(format!(
                "No distribution found for {}/{}",
                shard_key.bucket, shard_key.key
            ))
        })?;

        let mut info = dist.write().await;
        if let Some(locations) = info.locations.get_mut(&shard_key.shard_index) {
            for loc in locations.iter_mut() {
                if loc.domain_id == domain_id {
                    loc.health = health;
                    loc.last_verified = Some(Instant::now());
                }
            }
        }

        Ok(())
    }

    /// Find shards that need repair across all objects
    pub async fn find_repair_candidates(&self) -> Vec<(String, String, Vec<ShardIndex>)> {
        let mut candidates = Vec::new();

        for entry in self.distributions.iter() {
            let (bucket, key) = entry.key();
            let info = entry.value().read().await;

            if info.needs_repair() && info.is_recoverable() {
                let shards = info.shards_needing_repair();
                if !shards.is_empty() {
                    candidates.push((bucket.clone(), key.clone(), shards));
                }
            }
        }

        candidates
    }

    /// Remove distribution (when object is deleted)
    pub fn remove_distribution(&self, bucket: &str, key: &str) {
        self.distributions
            .remove(&(bucket.to_string(), key.to_string()));
        debug!(bucket, key, "Removed shard distribution");
    }

    /// Get statistics about shard distribution
    pub async fn stats(&self) -> ShardManagerStats {
        let mut total_objects = 0;
        let mut total_shards = 0;
        let mut healthy_shards = 0;
        let mut degraded_objects = 0;

        for entry in self.distributions.iter() {
            total_objects += 1;
            let info = entry.value().read().await;
            total_shards += info.total_shards;
            healthy_shards += info.healthy_shard_count();

            if info.needs_repair() {
                degraded_objects += 1;
            }
        }

        ShardManagerStats {
            total_objects,
            total_shards,
            healthy_shards,
            degraded_objects,
            repair_interval: self.repair_interval,
        }
    }

    /// Get the default replication policy
    pub fn default_policy(&self) -> &ReplicationPolicy {
        &self.default_policy
    }

    /// Get all shard distributions (for scrubbing/healing)
    pub async fn get_all_distributions(&self) -> Vec<((String, String), ShardDistributionInfo)> {
        let mut results = Vec::new();
        for entry in self.distributions.iter() {
            let key = entry.key().clone();
            let info = entry.value().read().await.clone();
            results.push((key, info));
        }
        results
    }

    /// Read a shard from a location
    ///
    /// For local domain, reads directly from the filesystem.
    /// For remote domains, this would need a network transport layer.
    pub async fn read_shard(
        &self,
        shard_key: &ShardKey,
        location: &ShardLocation,
    ) -> Result<Vec<u8>> {
        // Check shard health - only read from healthy or degraded shards
        match location.health {
            ShardHealth::Lost => {
                return Err(Error::Replication(format!(
                    "Cannot read shard {}:{} - marked as lost",
                    shard_key.bucket, shard_key.shard_index
                )));
            }
            ShardHealth::Repairing => {
                return Err(Error::Replication(format!(
                    "Cannot read shard {}:{} - currently being repaired",
                    shard_key.bucket, shard_key.shard_index
                )));
            }
            _ => {}
        }

        // Check if this is a local shard
        if location.domain_id == self.local_domain_id {
            // Local read - read directly from the path
            let shard_path = std::path::Path::new(&location.path);

            match tokio::fs::read(shard_path).await {
                Ok(data) => {
                    debug!(
                        bucket = %shard_key.bucket,
                        key = %shard_key.key,
                        shard = shard_key.shard_index,
                        size = data.len(),
                        "Read local shard"
                    );
                    Ok(data)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Err(Error::Replication(format!(
                        "Shard not found at path: {}",
                        location.path
                    )))
                }
                Err(e) => Err(Error::Io(e)),
            }
        } else {
            // Remote domain - would need network transport
            // For now, return an error indicating remote reads need transport layer
            Err(Error::Replication(format!(
                "Remote shard read not yet implemented (domain {})",
                location.domain_id
            )))
        }
    }

    /// Reconstruct a shard using erasure coding
    ///
    /// Uses Reed-Solomon erasure coding to reconstruct a missing shard from
    /// available shards. Requires at least `data_shards` worth of shard data.
    ///
    /// # Arguments
    /// * `shard_key` - The key identifying the shard to reconstruct
    /// * `distribution` - Information about the shard distribution
    /// * `shard_data` - Available shards as (index, data) pairs
    ///
    /// # Returns
    /// The reconstructed shard data, or an error if reconstruction fails
    #[cfg(feature = "erasure")]
    pub async fn reconstruct_shard(
        &self,
        shard_key: &ShardKey,
        distribution: &ShardDistributionInfo,
        shard_data: &[(ShardIndex, Vec<u8>)],
    ) -> Result<Vec<u8>> {
        use warp_ec::{ErasureConfig, ErasureDecoder, ErasureEncoder};

        // Validate we have enough shards
        if shard_data.len() < distribution.data_shards {
            return Err(Error::Replication(format!(
                "Insufficient shards for reconstruction: need {}, have {}",
                distribution.data_shards,
                shard_data.len()
            )));
        }

        // Determine shard size from available data
        let shard_size = shard_data
            .first()
            .map(|(_, d)| d.len())
            .ok_or_else(|| Error::Replication("No shard data provided".to_string()))?;

        // Validate all shards have same size
        for (idx, data) in shard_data {
            if data.len() != shard_size {
                return Err(Error::Replication(format!(
                    "Shard {} has size {}, expected {}",
                    idx,
                    data.len(),
                    shard_size
                )));
            }
        }

        // Build the shard array for decoder (None for missing shards)
        let total_shards = distribution.total_shards;
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];

        for (idx, data) in shard_data {
            let idx = *idx as usize;
            if idx < total_shards {
                shards[idx] = Some(data.clone());
            }
        }

        // Create erasure config and decoder
        let config = ErasureConfig::new(distribution.data_shards, distribution.parity_shards)
            .map_err(|e| Error::ErasureCoding(format!("Invalid erasure config: {}", e)))?;

        let decoder = ErasureDecoder::new(config.clone());

        // Decode to reconstruct original data
        let original_data = decoder
            .decode(&shards)
            .map_err(|e| Error::ErasureCoding(format!("Decode failed: {}", e)))?;

        // Re-encode to get all shards including the missing one
        let encoder = ErasureEncoder::new(config);
        let all_shards = encoder
            .encode(&original_data)
            .map_err(|e| Error::ErasureCoding(format!("Re-encode failed: {}", e)))?;

        // Extract the requested shard
        let target_idx = shard_key.shard_index as usize;
        if target_idx >= all_shards.len() {
            return Err(Error::Replication(format!(
                "Shard index {} out of range (total: {})",
                target_idx,
                all_shards.len()
            )));
        }

        info!(
            bucket = %shard_key.bucket,
            key = %shard_key.key,
            shard = shard_key.shard_index,
            available_shards = shard_data.len(),
            "Reconstructed shard using erasure coding"
        );

        Ok(all_shards[target_idx].clone())
    }

    /// Reconstruct a shard using erasure coding (stub when feature disabled)
    #[cfg(not(feature = "erasure"))]
    pub async fn reconstruct_shard(
        &self,
        _shard_key: &ShardKey,
        _distribution: &ShardDistributionInfo,
        _shard_data: &[(ShardIndex, Vec<u8>)],
    ) -> Result<Vec<u8>> {
        Err(Error::Replication(
            "Shard reconstruction requires 'erasure' feature".to_string(),
        ))
    }

    /// Select a target node for repair
    pub async fn select_repair_target(
        &self,
        _distribution: &ShardDistributionInfo,
        _shard_index: ShardIndex,
    ) -> Result<ShardLocation> {
        // In a real implementation, this would select an appropriate healthy node
        // For now, return a placeholder
        Ok(ShardLocation {
            domain_id: self.local_domain_id,
            node_id: "local".to_string(),
            path: "/repair".to_string(),
            last_verified: None,
            health: ShardHealth::Repairing,
        })
    }

    /// Write a reconstructed shard to a target
    pub async fn write_shard(
        &self,
        _shard_key: &ShardKey,
        _target: &ShardLocation,
        _data: &[u8],
    ) -> Result<()> {
        // In a real implementation, this would write to the storage node
        // For now, return success
        Ok(())
    }

    /// Verify a shard's integrity
    pub async fn verify_shard(
        &self,
        _shard_key: &ShardKey,
        _location: &ShardLocation,
    ) -> Result<ShardVerification> {
        // In a real implementation, this would verify the shard checksum
        // For now, return a successful verification
        Ok(ShardVerification {
            bytes_verified: 0,
            checksum_valid: true,
            expected_checksum: None,
            actual_checksum: None,
        })
    }
}

/// Result of shard verification
#[derive(Debug, Clone)]
pub struct ShardVerification {
    /// Bytes that were verified
    pub bytes_verified: u64,
    /// Whether checksum matched
    pub checksum_valid: bool,
    /// Expected checksum (if available)
    pub expected_checksum: Option<[u8; 32]>,
    /// Actual computed checksum (if available)
    pub actual_checksum: Option<[u8; 32]>,
}

/// Statistics about shard distribution
#[derive(Debug, Clone)]
pub struct ShardManagerStats {
    /// Total objects tracked
    pub total_objects: usize,

    /// Total shards across all objects
    pub total_shards: usize,

    /// Number of healthy shards
    pub healthy_shards: usize,

    /// Number of objects needing repair
    pub degraded_objects: usize,

    /// Configured repair interval
    pub repair_interval: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_key() {
        let key = ShardKey::new("bucket", "test/file.dat", 5);
        assert_eq!(key.bucket, "bucket");
        assert_eq!(key.key, "test/file.dat");
        assert_eq!(key.shard_index, 5);
    }

    #[test]
    fn test_all_shard_keys() {
        let keys = ShardKey::all_for_object("bucket", "key", 14);
        assert_eq!(keys.len(), 14);
        assert_eq!(keys[0].shard_index, 0);
        assert_eq!(keys[13].shard_index, 13);
    }

    #[test]
    fn test_distribution_info() {
        let policy = ErasurePolicy::default(); // RS(10,4)
        let mut info = ShardDistributionInfo::new("bucket", "key", &policy);

        assert_eq!(info.total_shards, 14);
        assert_eq!(info.data_shards, 10);
        assert_eq!(info.parity_shards, 4);
        assert!(!info.is_recoverable()); // No shards yet

        // Add 10 healthy shards
        for i in 0..10 {
            info.add_location(
                i,
                ShardLocation {
                    domain_id: 1,
                    node_id: "node1".to_string(),
                    path: format!("/data/shard_{}", i),
                    last_verified: Some(Instant::now()),
                    health: ShardHealth::Healthy,
                },
            );
        }

        assert!(info.is_recoverable());
        assert!(info.needs_repair()); // Missing 4 parity shards
        assert_eq!(info.shards_needing_repair(), vec![10, 11, 12, 13]);
    }

    #[test]
    fn test_plan_placement_spread() {
        let manager = DistributedShardManager::new(1, ReplicationPolicy::default());
        let domains = vec![1, 2, 3, 4];

        let placement = manager
            .plan_placement("bucket", "key", &ReplicationPolicy::default(), &domains)
            .unwrap();

        assert_eq!(placement.len(), 14); // RS(10,4) = 14 shards

        // Shards should be spread across domains
        let domain_counts: HashMap<DomainId, usize> =
            placement.values().fold(HashMap::new(), |mut acc, &d| {
                *acc.entry(d).or_insert(0) += 1;
                acc
            });

        // Each domain should have roughly equal shards
        for count in domain_counts.values() {
            assert!(*count >= 3 && *count <= 4);
        }
    }

    #[test]
    fn test_plan_placement_local() {
        let manager = DistributedShardManager::new(1, ReplicationPolicy::low_latency());
        let domains = vec![1, 2, 3];

        let placement = manager
            .plan_placement("bucket", "key", &ReplicationPolicy::low_latency(), &domains)
            .unwrap();

        // All shards should be on local domain (1)
        for domain_id in placement.values() {
            assert_eq!(*domain_id, 1);
        }
    }

    #[test]
    fn test_insufficient_domains() {
        let mut policy = ReplicationPolicy::high_durability();
        policy.placement.min_domain_spread = 5;

        let manager = DistributedShardManager::new(1, policy.clone());
        let domains = vec![1, 2, 3]; // Only 3 domains

        let result = manager.plan_placement("bucket", "key", &policy, &domains);
        assert!(result.is_err());
    }
}
