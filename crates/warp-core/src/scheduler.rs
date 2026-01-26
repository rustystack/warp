//! Scheduler module

use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// Chunk scheduling priority
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPriority {
    /// Chunk index
    pub chunk_index: u64,
    /// Priority score (higher = more urgent)
    pub score: i32,
}

impl Ord for ChunkPriority {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.cmp(&other.score)
    }
}

impl PartialOrd for ChunkPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Chunk scheduler with priority queue
pub struct ChunkScheduler {
    queue: BinaryHeap<ChunkPriority>,
}

impl ChunkScheduler {
    /// Create a new scheduler
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
        }
    }

    /// Add a chunk to the schedule
    pub fn schedule(&mut self, chunk_index: u64, score: i32) {
        self.queue.push(ChunkPriority { chunk_index, score });
    }

    /// Get the next chunk to process
    pub fn next_chunk(&mut self) -> Option<u64> {
        self.queue.pop().map(|p| p.chunk_index)
    }

    /// Check if scheduler is empty
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for ChunkScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        let scheduler = ChunkScheduler::new();
        assert!(scheduler.is_empty());
    }

    #[test]
    fn test_scheduler_default() {
        let scheduler = ChunkScheduler::default();
        assert!(scheduler.is_empty());
    }

    #[test]
    fn test_schedule_single_chunk() {
        let mut scheduler = ChunkScheduler::new();
        scheduler.schedule(0, 100);
        assert!(!scheduler.is_empty());

        let next = scheduler.next_chunk();
        assert_eq!(next, Some(0));
        assert!(scheduler.is_empty());
    }

    #[test]
    fn test_priority_ordering_higher_first() {
        let mut scheduler = ChunkScheduler::new();
        scheduler.schedule(1, 10);
        scheduler.schedule(2, 50);
        scheduler.schedule(3, 30);

        // Higher priority should come first
        assert_eq!(scheduler.next_chunk(), Some(2)); // score 50
        assert_eq!(scheduler.next_chunk(), Some(3)); // score 30
        assert_eq!(scheduler.next_chunk(), Some(1)); // score 10
        assert_eq!(scheduler.next_chunk(), None);
    }

    #[test]
    fn test_negative_scores() {
        let mut scheduler = ChunkScheduler::new();
        scheduler.schedule(1, -10);
        scheduler.schedule(2, -5);
        scheduler.schedule(3, -20);

        // Higher (less negative) should come first
        assert_eq!(scheduler.next_chunk(), Some(2)); // score -5
        assert_eq!(scheduler.next_chunk(), Some(1)); // score -10
        assert_eq!(scheduler.next_chunk(), Some(3)); // score -20
    }

    #[test]
    fn test_mixed_positive_negative_scores() {
        let mut scheduler = ChunkScheduler::new();
        scheduler.schedule(1, 10);
        scheduler.schedule(2, -5);
        scheduler.schedule(3, 0);

        assert_eq!(scheduler.next_chunk(), Some(1)); // score 10
        assert_eq!(scheduler.next_chunk(), Some(3)); // score 0
        assert_eq!(scheduler.next_chunk(), Some(2)); // score -5
    }

    #[test]
    fn test_equal_scores() {
        let mut scheduler = ChunkScheduler::new();
        scheduler.schedule(1, 50);
        scheduler.schedule(2, 50);
        scheduler.schedule(3, 50);

        // All should be processed (order may vary)
        let mut results = vec![];
        while let Some(chunk) = scheduler.next_chunk() {
            results.push(chunk);
        }
        results.sort();
        assert_eq!(results, vec![1, 2, 3]);
    }

    #[test]
    fn test_large_number_of_chunks() {
        let mut scheduler = ChunkScheduler::new();
        for i in 0..1000 {
            scheduler.schedule(i, (i % 100) as i32);
        }

        let mut count = 0;
        let mut prev_score = i32::MAX;
        while let Some(_chunk) = scheduler.next_chunk() {
            count += 1;
        }
        assert_eq!(count, 1000);
    }

    #[test]
    fn test_chunk_priority_comparison() {
        let p1 = ChunkPriority {
            chunk_index: 0,
            score: 10,
        };
        let p2 = ChunkPriority {
            chunk_index: 1,
            score: 20,
        };

        assert!(p2 > p1);
        assert!(p1 < p2);
    }

    #[test]
    fn test_chunk_priority_equality() {
        let p1 = ChunkPriority {
            chunk_index: 0,
            score: 10,
        };
        let p2 = ChunkPriority {
            chunk_index: 1,
            score: 10,
        };

        // Equal scores but different indices - should be equal for ordering purposes
        assert_eq!(p1.cmp(&p2), Ordering::Equal);
    }

    #[test]
    fn test_empty_scheduler_next() {
        let mut scheduler = ChunkScheduler::new();
        assert_eq!(scheduler.next_chunk(), None);
        assert_eq!(scheduler.next_chunk(), None);
    }
}
