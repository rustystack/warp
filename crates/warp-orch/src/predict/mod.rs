//! Predictive Pre-positioning & Access Pattern Detection
//!
//! This module provides:
//! - Access pattern detection (sequential, random, temporal, bursty, hot)
//! - Predictive analytics for chunk access
//! - Pre-positioning request generation
//! - Access analytics and insights

use chrono::{Datelike, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use warp_sched::{ChunkId, EdgeIdx};

/// Single access event record
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRecord {
    /// Chunk that was accessed
    pub chunk_id: ChunkId,
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,
    /// Edge that served the request
    pub edge_idx: EdgeIdx,
    /// Latency in milliseconds
    pub latency_ms: u64,
}

impl AccessRecord {
    /// Create a new access record
    pub fn new(chunk_id: ChunkId, timestamp_ms: u64, edge_idx: EdgeIdx, latency_ms: u64) -> Self {
        Self {
            chunk_id,
            timestamp_ms,
            edge_idx,
            latency_ms,
        }
    }
}

/// Detected access pattern types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessPattern {
    /// Sequential access pattern
    Sequential {
        /// Starting chunk ID
        start_chunk: ChunkId,
        /// Number of sequential chunks
        count: usize,
        /// Direction: +1 forward, -1 backward
        direction: i32,
    },
    /// Random access pattern
    Random {
        /// Randomly accessed chunks
        chunks: Vec<ChunkId>,
    },
    /// Temporal access pattern
    Temporal {
        /// Hour of day (0-23)
        hour_of_day: u8,
        /// Day of week (0-6, Monday=0)
        day_of_week: u8,
    },
    /// Bursty access pattern
    Bursty {
        /// Size of burst
        burst_size: usize,
        /// Interval between bursts in milliseconds
        interval_ms: u64,
    },
    /// Hot chunk pattern (frequently accessed)
    Hot {
        /// The hot chunk ID
        chunk_id: ChunkId,
        /// Number of accesses
        access_count: usize,
    },
}

/// Configuration for pattern detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternConfig {
    /// Time window for pattern detection in milliseconds
    pub window_size_ms: u64,
    /// Minimum length for sequential pattern
    pub min_sequential_length: usize,
    /// Access count threshold for "hot" classification
    pub hot_threshold: usize,
    /// Maximum records to keep in memory
    pub max_records: usize,
}

impl Default for PatternConfig {
    fn default() -> Self {
        Self {
            window_size_ms: 60_000,
            min_sequential_length: 5,
            hot_threshold: 10,
            max_records: 10_000,
        }
    }
}

/// Pattern detector for analyzing access patterns
pub struct PatternDetector {
    /// Configuration
    config: PatternConfig,
    /// Access records in chronological order
    records: VecDeque<AccessRecord>,
    /// Access count per chunk
    access_counts: HashMap<ChunkId, usize>,
}

impl PatternDetector {
    /// Create a new pattern detector
    pub fn new(config: PatternConfig) -> Self {
        Self {
            config,
            records: VecDeque::new(),
            access_counts: HashMap::new(),
        }
    }

    /// Record an access event
    pub fn record_access(&mut self, record: AccessRecord) {
        self.records.push_back(record);
        *self.access_counts.entry(record.chunk_id).or_insert(0) += 1;

        // Enforce max records limit
        while self.records.len() > self.config.max_records {
            if let Some(old_record) = self.records.pop_front() {
                if let Some(count) = self.access_counts.get_mut(&old_record.chunk_id) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.access_counts.remove(&old_record.chunk_id);
                    }
                }
            }
        }
    }

    /// Detect access patterns from recorded accesses
    pub fn detect_patterns(&self) -> Vec<AccessPattern> {
        let mut patterns = Vec::new();

        // Detect hot chunks
        for (&chunk_id, &count) in &self.access_counts {
            if count >= self.config.hot_threshold {
                patterns.push(AccessPattern::Hot {
                    chunk_id,
                    access_count: count,
                });
            }
        }

        // Detect sequential runs
        for (start_chunk, count, direction) in self.get_sequential_runs() {
            if count >= self.config.min_sequential_length {
                patterns.push(AccessPattern::Sequential {
                    start_chunk,
                    count,
                    direction,
                });
            }
        }

        // Detect temporal patterns
        if let Some(pattern) = self.detect_temporal_pattern() {
            patterns.push(pattern);
        }

        // Detect bursty patterns
        if let Some(pattern) = self.detect_bursty_pattern() {
            patterns.push(pattern);
        }

        patterns
    }

    /// Get hot chunks with access count above threshold
    pub fn get_hot_chunks(&self, threshold: usize) -> Vec<(ChunkId, usize)> {
        let mut hot_chunks: Vec<_> = self
            .access_counts
            .iter()
            .filter(|&(_, &count)| count >= threshold)
            .map(|(&id, &count)| (id, count))
            .collect();
        hot_chunks.sort_by(|a, b| b.1.cmp(&a.1));
        hot_chunks
    }

    /// Get sequential runs: (start_chunk, length, direction)
    pub fn get_sequential_runs(&self) -> Vec<(ChunkId, usize, i32)> {
        let mut runs = Vec::new();
        if self.records.len() < 2 {
            return runs;
        }

        let mut current_start = self.records[0].chunk_id;
        let mut current_count = 1;
        let mut current_direction = 0i32;

        for i in 1..self.records.len() {
            let prev_id = self.records[i - 1].chunk_id.get();
            let curr_id = self.records[i].chunk_id.get();
            let diff = curr_id as i64 - prev_id as i64;

            if diff.abs() == 1 {
                let dir = diff.signum() as i32;
                if current_count == 1 {
                    current_direction = dir;
                    current_count = 2;
                } else if dir == current_direction {
                    current_count += 1;
                } else {
                    if current_count >= 2 {
                        runs.push((current_start, current_count, current_direction));
                    }
                    current_start = self.records[i - 1].chunk_id;
                    current_count = 2;
                    current_direction = dir;
                }
            } else {
                if current_count >= 2 {
                    runs.push((current_start, current_count, current_direction));
                }
                current_start = self.records[i].chunk_id;
                current_count = 1;
                current_direction = 0;
            }
        }

        if current_count >= 2 {
            runs.push((current_start, current_count, current_direction));
        }

        runs
    }

    /// Clear records older than max_age_ms
    pub fn clear_old_records(&mut self, max_age_ms: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::ZERO)
            .as_millis() as u64;

        let cutoff = now.saturating_sub(max_age_ms);

        while let Some(record) = self.records.front() {
            if record.timestamp_ms < cutoff {
                let Some(old_record) = self.records.pop_front() else {
                    break;
                };
                if let Some(count) = self.access_counts.get_mut(&old_record.chunk_id) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.access_counts.remove(&old_record.chunk_id);
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Detect temporal pattern based on time of day
    fn detect_temporal_pattern(&self) -> Option<AccessPattern> {
        if self.records.is_empty() {
            return None;
        }

        // Count accesses by hour and day of week
        let mut hour_counts: HashMap<u8, usize> = HashMap::new();
        let mut day_counts: HashMap<u8, usize> = HashMap::new();

        for record in &self.records {
            let dt = chrono::DateTime::from_timestamp(
                (record.timestamp_ms / 1000) as i64,
                ((record.timestamp_ms % 1000) * 1_000_000) as u32,
            )?;
            let hour = dt.hour() as u8;
            let day = dt.weekday().num_days_from_monday() as u8;

            *hour_counts.entry(hour).or_insert(0) += 1;
            *day_counts.entry(day).or_insert(0) += 1;
        }

        // Find peak hour and day
        let peak_hour = hour_counts.iter().max_by_key(|&(_, &count)| count)?.0;
        let peak_day = day_counts.iter().max_by_key(|&(_, &count)| count)?.0;

        Some(AccessPattern::Temporal {
            hour_of_day: *peak_hour,
            day_of_week: *peak_day,
        })
    }

    /// Detect bursty access pattern
    fn detect_bursty_pattern(&self) -> Option<AccessPattern> {
        if self.records.len() < 10 {
            return None;
        }

        // Find clusters of accesses
        let mut gaps = Vec::new();
        for i in 1..self.records.len() {
            let gap = self.records[i]
                .timestamp_ms
                .saturating_sub(self.records[i - 1].timestamp_ms);
            gaps.push(gap);
        }

        // Calculate average gap
        let avg_gap = gaps.iter().sum::<u64>() / gaps.len() as u64;

        // Find large gaps (potential burst boundaries)
        let large_gap_threshold = avg_gap * 3;
        let large_gaps: Vec<_> = gaps
            .iter()
            .filter(|&&gap| gap > large_gap_threshold)
            .collect();

        if large_gaps.len() >= 2 {
            // Calculate average burst size
            let burst_count = large_gaps.len() + 1;
            let avg_burst_size = self.records.len() / burst_count;

            // Calculate average interval between bursts
            let avg_interval = large_gaps.iter().map(|&&g| g).sum::<u64>() / large_gaps.len() as u64;

            if avg_burst_size >= 5 {
                return Some(AccessPattern::Bursty {
                    burst_size: avg_burst_size,
                    interval_ms: avg_interval,
                });
            }
        }

        None
    }
}

/// Priority level for pre-positioning
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PrepositionPriority {
    /// Background pre-positioning
    Low,
    /// Anticipated access soon
    Medium,
    /// Imminent access expected
    High,
    /// User waiting
    Critical,
}

/// Request to pre-position chunks
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepositionRequest {
    /// Chunks to pre-position
    pub chunks: Vec<ChunkId>,
    /// Target edges where chunks should be positioned
    pub target_edges: Vec<EdgeIdx>,
    /// Priority level
    pub priority: PrepositionPriority,
    /// Reason for pre-positioning
    pub reason: String,
}

impl PrepositionRequest {
    /// Create a new pre-position request
    pub fn new(
        chunks: Vec<ChunkId>,
        target_edges: Vec<EdgeIdx>,
        priority: PrepositionPriority,
        reason: String,
    ) -> Self {
        Self {
            chunks,
            target_edges,
            priority,
            reason,
        }
    }
}

/// Configuration for predictor
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PredictorConfig {
    /// How many chunks to predict ahead
    pub lookahead_count: usize,
    /// Minimum confidence to act on prediction (0.0-1.0)
    pub min_confidence: f64,
    /// Score threshold for prefetching (0.0-1.0)
    pub prefetch_threshold: f64,
    /// Max chunks per preposition request
    pub max_preposition_batch: usize,
}

impl Default for PredictorConfig {
    fn default() -> Self {
        Self {
            lookahead_count: 10,
            min_confidence: 0.6,
            prefetch_threshold: 0.7,
            max_preposition_batch: 50,
        }
    }
}

/// Predictor for generating pre-positioning requests
pub struct Predictor {
    /// Configuration
    config: PredictorConfig,
    /// Recent predictions for scoring
    recent_predictions: HashMap<ChunkId, f64>,
}

impl Predictor {
    /// Create a new predictor
    pub fn new(config: PredictorConfig) -> Self {
        Self {
            config,
            recent_predictions: HashMap::new(),
        }
    }

    /// Predict next chunks to be accessed
    pub fn predict_next(&mut self, patterns: &[AccessPattern]) -> Vec<ChunkId> {
        let mut predictions = Vec::new();

        for pattern in patterns {
            match pattern {
                AccessPattern::Sequential {
                    start_chunk,
                    count,
                    direction,
                } => {
                    // Predict next chunks in sequence
                    let last_chunk_id = if *direction > 0 {
                        start_chunk.get() + (*count as u64)
                    } else {
                        start_chunk.get().saturating_sub(*count as u64)
                    };

                    for i in 0..self.config.lookahead_count {
                        let next_id = if *direction > 0 {
                            last_chunk_id + i as u64
                        } else {
                            last_chunk_id.saturating_sub(i as u64)
                        };
                        let chunk_id = ChunkId::new(next_id);
                        predictions.push(chunk_id);
                        self.recent_predictions.insert(chunk_id, 0.9);
                    }
                }
                AccessPattern::Hot {
                    chunk_id,
                    access_count: _,
                } => {
                    // Hot chunks likely to be accessed again
                    predictions.push(*chunk_id);
                    self.recent_predictions.insert(*chunk_id, 0.95);
                }
                _ => {}
            }
        }

        // Remove duplicates while preserving order
        let mut seen = std::collections::HashSet::new();
        predictions.retain(|&id| seen.insert(id));

        predictions
    }

    /// Generate pre-position requests from predictions
    pub fn generate_preposition_requests(
        &self,
        predictions: &[ChunkId],
        available_edges: &[EdgeIdx],
    ) -> Vec<PrepositionRequest> {
        if predictions.is_empty() || available_edges.is_empty() {
            return Vec::new();
        }

        let mut requests = Vec::new();
        let batch_size = self.config.max_preposition_batch.min(predictions.len());

        for chunk_batch in predictions.chunks(batch_size) {
            let confidence = chunk_batch
                .iter()
                .filter_map(|id| self.recent_predictions.get(id))
                .sum::<f64>()
                / chunk_batch.len() as f64;

            let priority = if confidence >= 0.9 {
                PrepositionPriority::High
            } else if confidence >= 0.7 {
                PrepositionPriority::Medium
            } else {
                PrepositionPriority::Low
            };

            if confidence >= self.config.min_confidence {
                requests.push(PrepositionRequest::new(
                    chunk_batch.to_vec(),
                    available_edges.to_vec(),
                    priority,
                    format!("Predicted access (confidence: {:.2})", confidence),
                ));
            }
        }

        requests
    }

    /// Score a prediction based on patterns
    pub fn score_prediction(&self, chunk_id: ChunkId, patterns: &[AccessPattern]) -> f64 {
        // Check recent predictions first
        if let Some(&score) = self.recent_predictions.get(&chunk_id) {
            return score;
        }

        let mut max_score: f64 = 0.0;

        for pattern in patterns {
            let score = match pattern {
                AccessPattern::Sequential {
                    start_chunk,
                    count,
                    direction,
                } => {
                    let range_start = start_chunk.get();
                    let range_end = if *direction > 0 {
                        range_start + *count as u64
                    } else {
                        range_start.saturating_sub(*count as u64)
                    };

                    let chunk_val = chunk_id.get();
                    if *direction > 0 && chunk_val >= range_end && chunk_val < range_end + 20 {
                        0.9 - ((chunk_val - range_end) as f64 * 0.05).min(0.4)
                    } else if *direction < 0 && chunk_val <= range_end && chunk_val + 20 > range_end
                    {
                        0.9 - ((range_end - chunk_val) as f64 * 0.05).min(0.4)
                    } else {
                        0.0
                    }
                }
                AccessPattern::Hot {
                    chunk_id: hot_id,
                    access_count,
                } => {
                    if *hot_id == chunk_id {
                        0.95
                    } else {
                        // Nearby chunks to hot chunks have some probability
                        let distance = (hot_id.get() as i64 - chunk_id.get() as i64).abs();
                        if distance < 5 {
                            0.5 - (distance as f64 * 0.08)
                        } else {
                            0.0
                        }
                    }
                }
                AccessPattern::Random { chunks } => {
                    if chunks.contains(&chunk_id) {
                        0.3
                    } else {
                        0.0
                    }
                }
                AccessPattern::Temporal { .. } => 0.4,
                AccessPattern::Bursty { .. } => 0.5,
            };

            max_score = max_score.max(score);
        }

        max_score
    }

    /// Get top prefetch candidates
    pub fn get_prefetch_candidates(&self, count: usize) -> Vec<ChunkId> {
        let mut candidates: Vec<_> = self
            .recent_predictions
            .iter()
            .filter(|&(_, &score)| score >= self.config.prefetch_threshold)
            .map(|(&id, &score)| (id, score))
            .collect();

        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        candidates.into_iter().take(count).map(|(id, _)| id).collect()
    }
}

/// Analytics for access patterns
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessAnalytics {
    /// Total number of accesses
    pub total_accesses: u64,
    /// Number of unique chunks accessed
    pub unique_chunks: usize,
    /// Average latency in milliseconds
    pub avg_latency_ms: f64,
    /// Ratio of sequential vs random access (0.0-1.0)
    pub sequential_ratio: f64,
    /// Ratio of accesses to hot chunks (0.0-1.0)
    pub hot_chunk_ratio: f64,
    /// Peak hour (0-23)
    pub peak_hour: u8,
}

impl AccessAnalytics {
    /// Calculate analytics from pattern detector
    pub fn from_detector(detector: &PatternDetector) -> Self {
        let total_accesses = detector.records.len() as u64;
        let unique_chunks = detector.access_counts.len();

        let avg_latency_ms = if !detector.records.is_empty() {
            detector
                .records
                .iter()
                .map(|r| r.latency_ms)
                .sum::<u64>() as f64
                / detector.records.len() as f64
        } else {
            0.0
        };

        let sequential_runs = detector.get_sequential_runs();
        let sequential_count: usize = sequential_runs.iter().map(|(_, count, _)| count).sum();
        let sequential_ratio = if total_accesses > 0 {
            sequential_count as f64 / total_accesses as f64
        } else {
            0.0
        };

        let hot_chunks = detector.get_hot_chunks(detector.config.hot_threshold);
        let hot_access_count: usize = hot_chunks.iter().map(|(_, count)| count).sum();
        let hot_chunk_ratio = if total_accesses > 0 {
            hot_access_count as f64 / total_accesses as f64
        } else {
            0.0
        };

        // Find peak hour
        let mut hour_counts: HashMap<u8, usize> = HashMap::new();
        for record in &detector.records {
            if let Some(dt) = chrono::DateTime::from_timestamp(
                (record.timestamp_ms / 1000) as i64,
                ((record.timestamp_ms % 1000) * 1_000_000) as u32,
            ) {
                let hour = dt.hour() as u8;
                *hour_counts.entry(hour).or_insert(0) += 1;
            }
        }
        let peak_hour = hour_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(hour, _)| hour)
            .unwrap_or(0);

        Self {
            total_accesses,
            unique_chunks,
            avg_latency_ms,
            sequential_ratio,
            hot_chunk_ratio,
            peak_hour,
        }
    }
}


#[cfg(test)]
mod tests;
