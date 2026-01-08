//! Workload prediction for SLAI-driven placement

use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Workload type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WorkloadType {
    /// Model training (forward + backward pass)
    Training,
    /// Model inference
    Inference,
    /// Data preprocessing
    Preprocessing,
    /// Checkpoint save/load
    Checkpointing,
    /// Model evaluation
    Evaluation,
    /// Data augmentation
    Augmentation,
    /// Unknown workload
    Unknown,
}

impl Default for WorkloadType {
    /// Returns the default workload type (Unknown)
    fn default() -> Self {
        Self::Unknown
    }
}

/// Training phase within a workload
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrainingPhase {
    /// Loading data into memory
    DataLoading,
    /// Forward pass
    Forward,
    /// Backward pass
    Backward,
    /// Optimizer step
    OptimizerStep,
    /// Saving checkpoint
    Checkpoint,
    /// Validation
    Validation,
    /// Idle between iterations
    Idle,
}

/// Prediction result from the workload predictor
#[derive(Debug, Clone)]
pub struct PredictionResult {
    /// Predicted workload type
    pub workload_type: WorkloadType,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Predicted next objects to access
    pub predicted_objects: Vec<String>,
    /// Predicted access time
    pub predicted_access_time: Option<Duration>,
    /// Current training phase (if applicable)
    pub training_phase: Option<TrainingPhase>,
    /// Prediction timestamp
    pub timestamp: Instant,
}

impl PredictionResult {
    /// Create a new prediction result
    pub fn new(workload_type: WorkloadType, confidence: f64) -> Self {
        Self {
            workload_type,
            confidence,
            predicted_objects: Vec::new(),
            predicted_access_time: None,
            training_phase: None,
            timestamp: Instant::now(),
        }
    }

    /// Set predicted objects
    pub fn with_objects(mut self, objects: Vec<String>) -> Self {
        self.predicted_objects = objects;
        self
    }

    /// Set predicted access time
    pub fn with_access_time(mut self, time: Duration) -> Self {
        self.predicted_access_time = Some(time);
        self
    }

    /// Set training phase
    pub fn with_phase(mut self, phase: TrainingPhase) -> Self {
        self.training_phase = Some(phase);
        self
    }
}

/// Workload pattern record for learning
#[derive(Debug, Clone)]
struct WorkloadPattern {
    /// Sequence of object accesses
    access_sequence: Vec<String>,
    /// Time intervals between accesses
    intervals: Vec<Duration>,
    /// Identified workload type
    workload_type: WorkloadType,
    /// Occurrence count
    count: u64,
    /// Last seen
    last_seen: Instant,
}

/// Workload predictor that learns from access patterns
pub struct WorkloadPredictor {
    /// Known workload patterns
    patterns: DashMap<String, WorkloadPattern>,
    /// Current workload context per session
    sessions: DashMap<String, SessionContext>,
    /// Model-specific patterns (bucket/prefix → patterns)
    model_patterns: DashMap<String, Vec<WorkloadPattern>>,
    /// Prediction statistics
    stats: RwLock<PredictorStats>,
    /// Pattern match threshold
    pattern_threshold: f64,
    /// Maximum pattern length to track
    max_pattern_length: usize,
}

/// Session context for tracking workload
#[derive(Debug, Clone)]
struct SessionContext {
    /// Session ID
    session_id: String,
    /// Recent object accesses
    recent_accesses: Vec<(String, Instant)>,
    /// Current detected workload
    current_workload: WorkloadType,
    /// Current training phase
    current_phase: Option<TrainingPhase>,
    /// Objects accessed in current phase
    phase_objects: Vec<String>,
    /// Start time
    started_at: Instant,
}

/// Predictor statistics
#[derive(Debug, Clone, Default)]
pub struct PredictorStats {
    /// Total predictions made
    pub predictions: u64,
    /// Correct predictions (validated)
    pub correct: u64,
    /// Patterns learned
    pub patterns_learned: usize,
    /// Active sessions
    pub active_sessions: usize,
}

impl PredictorStats {
    /// Get prediction accuracy
    pub fn accuracy(&self) -> f64 {
        if self.predictions == 0 {
            0.0
        } else {
            self.correct as f64 / self.predictions as f64
        }
    }
}

impl WorkloadPredictor {
    /// Create a new workload predictor
    pub fn new() -> Self {
        Self {
            patterns: DashMap::new(),
            sessions: DashMap::new(),
            model_patterns: DashMap::new(),
            stats: RwLock::new(PredictorStats::default()),
            pattern_threshold: 0.7,
            max_pattern_length: 100,
        }
    }

    /// Set pattern match threshold
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.pattern_threshold = threshold;
        self
    }

    /// Record an object access
    pub fn record_access(&self, session_id: &str, object_key: &str) {
        let now = Instant::now();

        // Update or create session context
        self.sessions
            .entry(session_id.to_string())
            .and_modify(|ctx| {
                ctx.recent_accesses.push((object_key.to_string(), now));
                if ctx.recent_accesses.len() > self.max_pattern_length {
                    ctx.recent_accesses.remove(0);
                }
                ctx.phase_objects.push(object_key.to_string());
            })
            .or_insert_with(|| SessionContext {
                session_id: session_id.to_string(),
                recent_accesses: vec![(object_key.to_string(), now)],
                current_workload: WorkloadType::Unknown,
                current_phase: None,
                phase_objects: vec![object_key.to_string()],
                started_at: now,
            });

        // Try to detect workload type from access patterns
        if let Some(mut ctx) = self.sessions.get_mut(session_id) {
            ctx.current_workload = self.classify_workload(&ctx);
        }
    }

    /// Classifies workload type by analyzing session context and access patterns
    fn classify_workload(&self, ctx: &SessionContext) -> WorkloadType {
        let accesses = &ctx.recent_accesses;
        if accesses.is_empty() {
            return WorkloadType::Unknown;
        }

        // Analyze access patterns
        let keys: Vec<&str> = accesses.iter().map(|(k, _)| k.as_str()).collect();

        // Check for checkpoint patterns
        if keys.iter().any(|k| {
            k.contains("checkpoint")
                || k.contains(".ckpt")
                || k.contains(".pt")
                || k.contains(".safetensors")
        }) {
            return WorkloadType::Checkpointing;
        }

        // Check for training data patterns (sequential batches)
        if self.is_sequential_batch_pattern(&keys) {
            return WorkloadType::Training;
        }

        // Check for preprocessing patterns
        if keys
            .iter()
            .any(|k| k.contains("preprocess") || k.contains("transform") || k.contains("augment"))
        {
            return WorkloadType::Preprocessing;
        }

        // Check for evaluation patterns
        if keys
            .iter()
            .any(|k| k.contains("eval") || k.contains("valid") || k.contains("test"))
        {
            return WorkloadType::Evaluation;
        }

        // Default to inference if we see model files being read
        if keys
            .iter()
            .any(|k| k.contains("model") || k.contains("weight") || k.ends_with(".bin"))
        {
            return WorkloadType::Inference;
        }

        WorkloadType::Unknown
    }

    /// Checks if access pattern looks like sequential batch files (e.g., batch_0, batch_1, batch_2)
    fn is_sequential_batch_pattern(&self, keys: &[&str]) -> bool {
        if keys.len() < 3 {
            return false;
        }

        // Look for numbered patterns like batch_0, batch_1, etc.
        let mut numbers: Vec<i64> = Vec::new();
        for key in keys {
            // Try to extract numbers from the key
            let num_str: String = key.chars().filter(|c| c.is_ascii_digit()).collect();
            if let Ok(num) = num_str.parse::<i64>() {
                numbers.push(num);
            }
        }

        if numbers.len() >= 3 {
            // Check if numbers are roughly sequential
            let mut ascending = 0;
            for window in numbers.windows(2) {
                if window[1] > window[0] && window[1] - window[0] <= 10 {
                    ascending += 1;
                }
            }
            return ascending as f64 / (numbers.len() - 1) as f64 > 0.5;
        }

        false
    }

    /// Predict next objects to access
    pub fn predict(&self, session_id: &str) -> PredictionResult {
        let mut stats = self.stats.write();
        stats.predictions += 1;
        drop(stats);

        // Get session context
        let ctx = match self.sessions.get(session_id) {
            Some(ctx) => ctx.clone(),
            None => {
                return PredictionResult::new(WorkloadType::Unknown, 0.0);
            }
        };

        let workload = ctx.current_workload;
        let confidence = if workload == WorkloadType::Unknown {
            0.3
        } else {
            0.75
        };

        let mut result = PredictionResult::new(workload, confidence);

        // Predict next objects based on workload type
        match workload {
            WorkloadType::Training => {
                // Predict next batch files
                result = result.with_phase(TrainingPhase::DataLoading);
                result.predicted_objects = self.predict_next_batches(&ctx);
            }
            WorkloadType::Checkpointing => {
                // Predict checkpoint-related files
                result = result.with_phase(TrainingPhase::Checkpoint);
            }
            WorkloadType::Inference => {
                // Predict model weight files
                result.predicted_objects = self.predict_model_files(&ctx);
            }
            _ => {}
        }

        result
    }

    /// Predicts next batch files by incrementing batch numbers from recent accesses
    fn predict_next_batches(&self, ctx: &SessionContext) -> Vec<String> {
        let mut predicted = Vec::new();

        // Get recent batch numbers and predict next ones
        for (key, _) in ctx.recent_accesses.iter().rev().take(5) {
            // Try to extract batch number and increment
            if let Some(next_key) = self.increment_batch_number(key) {
                if !predicted.contains(&next_key) {
                    predicted.push(next_key);
                }
            }
        }

        predicted.truncate(10); // Limit predictions
        predicted
    }

    /// Increments the last numeric sequence in a key to predict the next batch file
    fn increment_batch_number(&self, key: &str) -> Option<String> {
        // Find the last number in the key and increment it
        let chars: Vec<char> = key.chars().collect();
        let mut num_start = None;
        let mut num_end = None;

        for (i, c) in chars.iter().enumerate().rev() {
            if c.is_ascii_digit() {
                if num_end.is_none() {
                    num_end = Some(i);
                }
                num_start = Some(i);
            } else if num_end.is_some() {
                break;
            }
        }

        if let (Some(start), Some(end)) = (num_start, num_end) {
            let num_str: String = chars[start..=end].iter().collect();
            if let Ok(num) = num_str.parse::<u64>() {
                let new_num = format!("{:0width$}", num + 1, width = num_str.len());
                let mut result: String = chars[..start].iter().collect();
                result.push_str(&new_num);
                result.extend(chars[end + 1..].iter());
                return Some(result);
            }
        }

        None
    }

    /// Predicts related model weight files based on recently accessed model files
    fn predict_model_files(&self, ctx: &SessionContext) -> Vec<String> {
        // Get related model files based on recent accesses
        let mut predicted = Vec::new();

        for (key, _) in &ctx.recent_accesses {
            // If we see a model file, predict related weight files
            if key.contains("model") {
                // Common patterns for model weight files
                let base = key
                    .trim_end_matches(".bin")
                    .trim_end_matches(".pt")
                    .trim_end_matches(".safetensors");

                predicted.push(format!("{}.bin", base));
                predicted.push(format!("{}.safetensors", base));
            }
        }

        predicted.truncate(20);
        predicted
    }

    /// Set current training phase for a session
    pub fn set_phase(&self, session_id: &str, phase: TrainingPhase) {
        if let Some(mut ctx) = self.sessions.get_mut(session_id) {
            ctx.current_phase = Some(phase);
            ctx.phase_objects.clear();
        }
    }

    /// Get current workload type for a session
    pub fn get_workload(&self, session_id: &str) -> WorkloadType {
        self.sessions
            .get(session_id)
            .map(|ctx| ctx.current_workload)
            .unwrap_or(WorkloadType::Unknown)
    }

    /// Validate a prediction (for learning)
    pub fn validate_prediction(
        &self,
        _session_id: &str,
        _actual_object: &str,
        was_predicted: bool,
    ) {
        if was_predicted {
            self.stats.write().correct += 1;
        }
    }

    /// End a session
    pub fn end_session(&self, session_id: &str) {
        if let Some((_, ctx)) = self.sessions.remove(session_id) {
            // Learn from the session pattern
            if ctx.recent_accesses.len() >= 5 {
                let pattern_key = format!("{}:{:?}", session_id, ctx.current_workload);
                self.patterns.insert(
                    pattern_key,
                    WorkloadPattern {
                        access_sequence: ctx
                            .recent_accesses
                            .iter()
                            .map(|(k, _)| k.clone())
                            .collect(),
                        intervals: Vec::new(), // Could compute intervals
                        workload_type: ctx.current_workload,
                        count: 1,
                        last_seen: Instant::now(),
                    },
                );
            }
        }

        self.stats.write().active_sessions = self.sessions.len();
    }

    /// Get predictor statistics
    pub fn stats(&self) -> PredictorStats {
        let mut stats = self.stats.read().clone();
        stats.active_sessions = self.sessions.len();
        stats.patterns_learned = self.patterns.len();
        stats
    }
}

impl Default for WorkloadPredictor {
    /// Creates a new workload predictor with default settings
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workload_predictor_creation() {
        let predictor = WorkloadPredictor::new();
        assert_eq!(predictor.stats().predictions, 0);
    }

    #[test]
    fn test_record_access() {
        let predictor = WorkloadPredictor::new();

        predictor.record_access("session1", "batch_0.bin");
        predictor.record_access("session1", "batch_1.bin");
        predictor.record_access("session1", "batch_2.bin");

        let workload = predictor.get_workload("session1");
        assert_eq!(workload, WorkloadType::Training);
    }

    #[test]
    fn test_checkpoint_detection() {
        let predictor = WorkloadPredictor::new();

        predictor.record_access("session1", "model_checkpoint_epoch_10.pt");

        let workload = predictor.get_workload("session1");
        assert_eq!(workload, WorkloadType::Checkpointing);
    }

    #[test]
    fn test_prediction() {
        let predictor = WorkloadPredictor::new();

        predictor.record_access("session1", "batch_0.bin");
        predictor.record_access("session1", "batch_1.bin");
        predictor.record_access("session1", "batch_2.bin");

        let prediction = predictor.predict("session1");
        assert_eq!(prediction.workload_type, WorkloadType::Training);
        assert!(prediction.confidence > 0.5);
    }

    #[test]
    fn test_increment_batch_number() {
        let predictor = WorkloadPredictor::new();

        assert_eq!(
            predictor.increment_batch_number("batch_001.bin"),
            Some("batch_002.bin".to_string())
        );
        assert_eq!(
            predictor.increment_batch_number("data/train/batch_99.pt"),
            Some("data/train/batch_100.pt".to_string())
        );
    }

    #[test]
    fn test_session_lifecycle() {
        let predictor = WorkloadPredictor::new();

        predictor.record_access("session1", "file1");
        predictor.record_access("session1", "file2");
        predictor.record_access("session1", "file3");
        predictor.record_access("session1", "file4");
        predictor.record_access("session1", "file5");

        assert_eq!(predictor.stats().active_sessions, 1);

        predictor.end_session("session1");
        assert_eq!(predictor.stats().active_sessions, 0);
        assert!(predictor.stats().patterns_learned > 0);
    }
}
