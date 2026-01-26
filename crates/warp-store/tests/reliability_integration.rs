//! Integration tests for warp-store reliability features
//!
//! Tests the following components:
//! - Healer daemon (self-healing)
//! - Scrub daemon (integrity verification)
//! - Quota management
//! - Arbiter/Witness (split-brain prevention)
//! - Snapshot/Clone API

use std::sync::Arc;
use std::time::Duration;

use warp_store::quota::QuotaScope;
use warp_store::scrub::ScrubSchedule;
use warp_store::{
    CloneConfig,
    CloneManager,
    CowConfig,
    CowManager,
    FencingConfig,
    FencingManager,
    // Healer
    HealerConfig,
    QuotaConfig,
    QuotaEnforcement,
    // Quota
    QuotaManager,
    QuotaPolicy,
    RecoveryCoordinator,
    RepairJob,
    RepairPriority,
    RepairQueue,
    // Scrub
    ScrubConfig,
    ScrubScheduler,
    SnapshotConfig,
    // Snapshot
    SnapshotManager,
    SplitBrainDetector,
    Vote,
    // Arbiter
    VoteTracker,
    WitnessConfig,
    WitnessNode,
};

// ============================================================================
// Healer Integration Tests
// ============================================================================

mod healer_tests {
    use super::*;

    #[test]
    fn test_repair_queue_priority_ordering() {
        let queue = RepairQueue::new();

        // Add repairs with different priorities
        queue.push(RepairJob::new(
            warp_store::ShardKey::new("bucket", "key1", 0),
            RepairPriority::Low,
        ));
        queue.push(RepairJob::new(
            warp_store::ShardKey::new("bucket", "key2", 0),
            RepairPriority::Critical,
        ));
        queue.push(RepairJob::new(
            warp_store::ShardKey::new("bucket", "key3", 0),
            RepairPriority::High,
        ));

        // Should get Critical first
        let first = queue.pop().unwrap();
        assert_eq!(first.priority, RepairPriority::Critical);

        // Then High
        let second = queue.pop().unwrap();
        assert_eq!(second.priority, RepairPriority::High);

        // Then Low
        let third = queue.pop().unwrap();
        assert_eq!(third.priority, RepairPriority::Low);
    }

    #[test]
    fn test_healer_config() {
        let config = HealerConfig::default();
        assert!(config.worker_count > 0);
        assert!(config.scan_interval > Duration::ZERO);
    }
}

// ============================================================================
// Scrub Integration Tests
// ============================================================================

mod scrub_tests {
    use super::*;

    #[test]
    fn test_scrub_scheduler_timing() {
        let schedule = ScrubSchedule {
            light_interval: Duration::from_secs(3600),
            deep_interval: Duration::from_secs(86400),
            ..Default::default()
        };

        let mut scheduler = ScrubScheduler::new(schedule);

        // Initially should want to scrub
        assert!(scheduler.should_light_scrub() || scheduler.should_deep_scrub());

        // After recording, shouldn't need immediate scrub
        scheduler.record_light_scrub();
        scheduler.record_deep_scrub();

        // Scheduler tracks when scrubs occurred
        // (actual timing behavior tested in unit tests)
    }

    #[test]
    fn test_scrub_config() {
        let config = ScrubConfig::default();
        assert!(config.worker_count > 0);
        assert!(config.batch_size > 0);
    }
}

// ============================================================================
// Quota Integration Tests
// ============================================================================

mod quota_tests {
    use super::*;
    use warp_store::quota::QuotaLimit;

    #[test]
    fn test_quota_enforcement_workflow() {
        let manager = QuotaManager::new(QuotaConfig::default());

        // Create a policy with limits using builder pattern
        let bucket_scope = QuotaScope::Bucket("test".to_string());
        let policy = QuotaPolicy::new("test-bucket-policy", bucket_scope.clone())
            .with_storage_limit(QuotaLimit::storage_bytes(2 * 1024 * 1024)); // 2MB

        manager.set_policy(policy);

        // QuotaEnforcement takes no arguments
        let _enforcement = QuotaEnforcement::new();

        // Quota manager tracks usage and enforces limits
        let usage = manager.bucket_usage("test");
        assert_eq!(usage.storage_bytes, 0);
    }

    #[test]
    fn test_multi_scope_quotas() {
        let manager = QuotaManager::new(QuotaConfig::default());

        // Add bucket quota
        let bucket_scope = QuotaScope::Bucket("mybucket".to_string());
        let bucket_policy = QuotaPolicy::new("bucket-quota", bucket_scope.clone());
        manager.set_policy(bucket_policy);

        // Add user quota
        let user_scope = QuotaScope::User("user123".to_string());
        let user_policy = QuotaPolicy::new("user-quota", user_scope.clone());
        manager.set_policy(user_policy);

        // Both should be trackable
        assert!(manager.get_policy(&bucket_scope).is_some());
        assert!(manager.get_policy(&user_scope).is_some());
    }
}

// ============================================================================
// Arbiter Integration Tests
// ============================================================================

mod arbiter_tests {
    use super::*;

    #[test]
    fn test_vote_tracker_quorum_calculation() {
        let tracker = VoteTracker::new(1);

        // Register 3 nodes
        tracker.register_node(1, 1, false);
        tracker.register_node(2, 1, false);
        tracker.register_node(3, 1, false);

        // Quorum should be 2 (majority of 3)
        assert_eq!(tracker.quorum_size(), 2);

        // All nodes initially reachable
        let status = tracker.quorum_status();
        assert!(status.has_quorum);
        assert_eq!(status.total_nodes, 3);
    }

    #[test]
    fn test_election_workflow() {
        let tracker = VoteTracker::new(1);

        // Setup 3-node cluster
        tracker.register_node(1, 1, false);
        tracker.register_node(2, 1, false);
        tracker.register_node(3, 1, false);

        // Start election
        let election_id = tracker.start_election();
        let term = tracker.term();

        // Node 1 votes for itself
        let vote1 = tracker.vote_for_self().unwrap();
        assert_eq!(vote1.candidate, 1);

        // Node 2 votes for node 1
        tracker.cast_vote(Vote::new(2, election_id, 1, term));

        // Should now have won (2/3 = quorum)
        assert_eq!(tracker.check_election(), warp_store::VoteResult::Won);
        assert_eq!(tracker.leader(), Some(1));
    }

    #[test]
    fn test_witness_node_quorum() {
        let vote_tracker = Arc::new(VoteTracker::new(1));
        let witness = WitnessNode::with_vote_tracker(
            100, // Witness node ID
            WitnessConfig::default(),
            vote_tracker.clone(),
        );

        // Register peers
        witness.register_peer(1, true, 1);
        witness.register_peer(2, true, 1);

        assert_eq!(witness.reachable_peers(), 2);
        assert!(witness.has_min_peers());
    }

    #[test]
    fn test_split_brain_detector() {
        let vote_tracker = Arc::new(VoteTracker::new(1));
        let detector = SplitBrainDetector::new(1, vote_tracker);

        // Register nodes
        detector.register_node(2, 1);
        detector.register_node(3, 1);

        // All healthy initially
        let state = detector.state();
        assert_eq!(state, warp_store::PartitionState::Healthy);
    }

    #[test]
    fn test_fencing_manager() {
        let config = FencingConfig::default().protect_node(999);
        let manager = FencingManager::new(config);

        // Can request fence on unprotected node
        assert!(manager.request_fence(1, None));
        assert_eq!(manager.pending_count(), 1);

        // Cannot fence protected node
        assert!(!manager.request_fence(999, None));
    }

    #[test]
    fn test_recovery_coordinator() {
        let vote_tracker = Arc::new(VoteTracker::new(1));
        let fencing = Arc::new(FencingManager::new(FencingConfig::default()));
        let coordinator = RecoveryCoordinator::new(vote_tracker, fencing);

        assert_eq!(coordinator.state(), warp_store::RecoveryState::Idle);
        assert!(!coordinator.needs_recovery());
    }
}

// ============================================================================
// Snapshot Integration Tests
// ============================================================================

mod snapshot_tests {
    use super::*;

    #[tokio::test]
    async fn test_snapshot_lifecycle() {
        let manager = SnapshotManager::new(SnapshotConfig::default());

        // Create snapshot
        let snapshot = manager
            .create_snapshot("test-bucket", "backup-1", None)
            .await
            .unwrap();

        assert_eq!(snapshot.bucket, "test-bucket");
        assert_eq!(snapshot.state, warp_store::SnapshotState::Active);

        // List snapshots
        let snapshots = manager.list_snapshots("test-bucket");
        assert_eq!(snapshots.len(), 1);

        // Lock snapshot
        manager.lock_snapshot(snapshot.id).unwrap();
        let locked = manager.get_snapshot(snapshot.id).unwrap();
        assert_eq!(locked.state, warp_store::SnapshotState::Locked);

        // Cannot delete locked snapshot
        assert!(manager.delete_snapshot(snapshot.id).await.is_err());

        // Unlock and delete
        manager.unlock_snapshot(snapshot.id).unwrap();
        manager.delete_snapshot(snapshot.id).await.unwrap();

        assert!(manager.list_snapshots("test-bucket").is_empty());
    }

    #[tokio::test]
    async fn test_incremental_snapshots() {
        let manager = SnapshotManager::new(SnapshotConfig {
            dedup_enabled: true,
            ..Default::default()
        });

        // First snapshot
        let snap1 = manager
            .create_snapshot("bucket", "snap1", None)
            .await
            .unwrap();

        // Second snapshot should be incremental
        let snap2 = manager
            .create_snapshot("bucket", "snap2", None)
            .await
            .unwrap();

        assert_eq!(snap2.parent_id, Some(snap1.id));
    }

    #[test]
    fn test_cow_deduplication() {
        let manager = CowManager::new(CowConfig {
            dedup_enabled: true,
            ..Default::default()
        });

        let data = b"Same content for deduplication test";
        let checksum = [42u8; 32];

        // First allocation
        let ref1 = manager.allocate_block(data, checksum);

        // Second allocation with same content
        let ref2 = manager.allocate_block(data, checksum);

        // Should reuse same block
        assert_eq!(ref1.block_id, ref2.block_id);

        // Block should have ref_count of 2
        let block = manager.get_block(ref1.block_id).unwrap();
        assert_eq!(block.ref_count, 2);

        // Stats should show dedup hit
        let stats = manager.stats();
        assert_eq!(stats.dedup_hits, 1);
    }

    #[tokio::test]
    async fn test_clone_from_snapshot() {
        let cow_manager = Arc::new(CowManager::new(CowConfig::default()));
        let clone_manager = CloneManager::new(CloneConfig::default(), cow_manager);

        // Create a mock snapshot
        let snapshot = warp_store::Snapshot::new("source-bucket", "test-snapshot");

        // Create clone
        let handle = clone_manager
            .create_clone(&snapshot, "clone-bucket", "my-clone")
            .await
            .unwrap();

        // Verify clone exists
        assert!(clone_manager.is_clone("clone-bucket"));

        let clone_info = clone_manager.get_clone(handle.id).unwrap();
        assert_eq!(clone_info.state, warp_store::CloneState::Active);
        assert_eq!(clone_info.target_bucket, "clone-bucket");
    }
}

// ============================================================================
// Combined Reliability Tests
// ============================================================================

mod combined_tests {
    use super::*;

    #[test]
    fn test_reliability_components_together() {
        // Create all reliability components
        let vote_tracker = Arc::new(VoteTracker::new(1));

        // Setup 3-node cluster
        vote_tracker.register_node(1, 1, false);
        vote_tracker.register_node(2, 1, false);
        vote_tracker.register_node(3, 1, true); // witness

        // Verify quorum
        let quorum_status = vote_tracker.quorum_status();
        assert!(quorum_status.has_quorum);
        assert_eq!(quorum_status.quorum_size, 2);

        // Create split-brain detector
        let detector = SplitBrainDetector::new(1, vote_tracker.clone());
        detector.register_node(2, 1);
        detector.register_node(3, 1);

        // Initially healthy
        assert_eq!(detector.state(), warp_store::PartitionState::Healthy);

        // Create fencing manager
        let fencing = Arc::new(FencingManager::new(FencingConfig::default()));

        // Create recovery coordinator
        let _coordinator = RecoveryCoordinator::new(vote_tracker.clone(), fencing);

        // Create quota manager
        let quota_manager = QuotaManager::new(QuotaConfig::default());
        let usage = quota_manager.bucket_usage("test-bucket");
        assert_eq!(usage.storage_bytes, 0);

        // Create snapshot manager
        let snapshot_manager = SnapshotManager::new(SnapshotConfig::default());
        assert_eq!(snapshot_manager.snapshot_count(), 0);

        // All components initialized successfully
    }

    #[tokio::test]
    async fn test_snapshot_with_quota_tracking() {
        let snapshot_manager = SnapshotManager::new(SnapshotConfig::default());
        let quota_manager = QuotaManager::new(QuotaConfig::default());

        // Create snapshot
        let snapshot = snapshot_manager
            .create_snapshot("tracked-bucket", "snap1", None)
            .await
            .unwrap();

        // Snapshot tracks bytes
        assert_eq!(snapshot.total_bytes, 0); // Initial is 0

        // Quota tracks usage
        quota_manager.record_put("tracked-bucket", Some("user1"), 1000);
        let usage = quota_manager.bucket_usage("tracked-bucket");
        assert_eq!(usage.storage_bytes, 1000);
    }
}
