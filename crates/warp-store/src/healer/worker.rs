//! Repair worker implementation

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use super::{HealerMetrics, RepairJob, RepairQueue};
use crate::error::{Error, Result};
use crate::replication::{
    DistributedShardManager, ShardHealth, ShardIndex, ShardKey, ShardLocation,
};

/// Result of a repair operation
#[derive(Debug, Clone)]
pub struct RepairResult {
    /// The shard that was repaired
    pub shard_key: ShardKey,
    /// Whether the repair succeeded
    pub success: bool,
    /// Time taken for the repair
    pub duration: Duration,
    /// Error message if failed
    pub error: Option<String>,
    /// Bytes transferred during repair
    pub bytes_transferred: u64,
}

/// A repair worker that processes jobs from the queue
pub struct RepairWorker {
    /// Worker ID
    id: usize,

    /// Reference to the repair queue
    queue: Arc<RepairQueue>,

    /// Shard manager for performing repairs
    shard_manager: Arc<DistributedShardManager>,

    /// Metrics collector
    metrics: Arc<HealerMetrics>,

    /// Timeout for repair operations
    timeout: Duration,
}

impl RepairWorker {
    /// Create a new repair worker
    pub fn new(
        id: usize,
        queue: Arc<RepairQueue>,
        shard_manager: Arc<DistributedShardManager>,
        metrics: Arc<HealerMetrics>,
        timeout: Duration,
    ) -> Self {
        Self {
            id,
            queue,
            shard_manager,
            metrics,
            timeout,
        }
    }

    /// Process one job from the queue
    ///
    /// Returns Ok(Some(result)) if a job was processed,
    /// Ok(None) if the queue was empty,
    /// Err if an error occurred.
    pub async fn process_one(&self) -> Result<Option<RepairResult>> {
        // Pop a job from the queue
        let job = match self.queue.pop() {
            Some(j) => j,
            None => return Ok(None),
        };

        debug!(
            worker_id = self.id,
            job_id = job.id,
            shard = ?job.shard_key,
            priority = ?job.priority,
            "Processing repair job"
        );

        // Perform the repair
        let result = self.repair_shard(&job).await;

        // Handle the result
        match &result {
            Ok(r) if r.success => {
                self.queue.mark_completed();
                self.metrics.record_repair_success(r.duration);
                info!(
                    worker_id = self.id,
                    shard = ?job.shard_key,
                    duration = ?r.duration,
                    bytes = r.bytes_transferred,
                    "Repair successful"
                );
            }
            Ok(r) => {
                self.metrics.record_repair_failure();
                warn!(
                    worker_id = self.id,
                    shard = ?job.shard_key,
                    error = ?r.error,
                    "Repair failed"
                );
                self.queue.requeue(job);
            }
            Err(e) => {
                self.metrics.record_repair_failure();
                error!(
                    worker_id = self.id,
                    shard = ?job.shard_key,
                    error = %e,
                    "Repair error"
                );
                self.queue.requeue(job);
            }
        }

        result.map(Some)
    }

    /// Perform the actual shard repair
    async fn repair_shard(&self, job: &RepairJob) -> Result<RepairResult> {
        let start = Instant::now();

        // Apply timeout
        let repair_future = self.do_repair(&job.shard_key);
        let result = tokio::time::timeout(self.timeout, repair_future).await;

        let duration = start.elapsed();

        match result {
            Ok(Ok(bytes)) => Ok(RepairResult {
                shard_key: job.shard_key.clone(),
                success: true,
                duration,
                error: None,
                bytes_transferred: bytes,
            }),
            Ok(Err(e)) => Ok(RepairResult {
                shard_key: job.shard_key.clone(),
                success: false,
                duration,
                error: Some(e.to_string()),
                bytes_transferred: 0,
            }),
            Err(_) => Ok(RepairResult {
                shard_key: job.shard_key.clone(),
                success: false,
                duration,
                error: Some("Repair timed out".to_string()),
                bytes_transferred: 0,
            }),
        }
    }

    /// Perform repair operation
    async fn do_repair(&self, shard_key: &ShardKey) -> Result<u64> {
        // Step 1: Get object distribution info
        let dist_lock = self
            .shard_manager
            .get_distribution(&shard_key.bucket, &shard_key.key)
            .ok_or_else(|| Error::ObjectNotFound {
                bucket: shard_key.bucket.clone(),
                key: shard_key.key.clone(),
            })?;

        let distribution = dist_lock.read().await;

        // Step 2: Find healthy shards to reconstruct from
        let mut healthy_shards: Vec<(ShardIndex, &ShardLocation)> = Vec::new();
        for (idx, locations) in &distribution.locations {
            for loc in locations {
                if loc.health == ShardHealth::Healthy {
                    healthy_shards.push((*idx, loc));
                    break; // Only need one healthy location per shard
                }
            }
        }

        let data_shards = distribution.data_shards;

        if healthy_shards.len() < data_shards {
            return Err(Error::InsufficientShards {
                available: healthy_shards.len(),
                required: data_shards,
            });
        }

        // Step 3: Read enough healthy shards for reconstruction
        let mut shard_data: Vec<(ShardIndex, Vec<u8>)> = Vec::with_capacity(data_shards);
        let mut bytes_read = 0u64;

        for (idx, location) in healthy_shards.iter().take(data_shards + 1) {
            match self.shard_manager.read_shard(shard_key, location).await {
                Ok(data) => {
                    bytes_read += data.len() as u64;
                    shard_data.push((*idx, data));
                    if shard_data.len() >= data_shards {
                        break;
                    }
                }
                Err(e) => {
                    warn!(shard_idx = idx, error = %e, "Failed to read shard");
                }
            }
        }

        if shard_data.len() < data_shards {
            return Err(Error::InsufficientShards {
                available: shard_data.len(),
                required: data_shards,
            });
        }

        // Step 4: Reconstruct the missing shard using erasure coding
        let reconstructed: Vec<u8> = self
            .shard_manager
            .reconstruct_shard(shard_key, &distribution, &shard_data)
            .await?;

        let bytes_written = reconstructed.len() as u64;

        // Step 5: Find a healthy node to place the reconstructed shard
        let target_node = self
            .shard_manager
            .select_repair_target(&distribution, shard_key.shard_index)
            .await?;

        // Step 6: Write the reconstructed shard
        self.shard_manager
            .write_shard(shard_key, &target_node, &reconstructed)
            .await?;

        // Step 7: Update shard health to Healthy
        // Need to drop the read lock before updating
        drop(distribution);

        self.shard_manager
            .update_shard_health(shard_key, target_node.domain_id, ShardHealth::Healthy)
            .await?;

        Ok(bytes_read + bytes_written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repair_result() {
        let result = RepairResult {
            shard_key: ShardKey::new("bucket", "key", 0),
            success: true,
            duration: Duration::from_secs(1),
            error: None,
            bytes_transferred: 1024,
        };

        assert!(result.success);
        assert!(result.error.is_none());
    }
}
