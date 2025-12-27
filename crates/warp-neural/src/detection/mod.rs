//! Content detection for neural compression suitability
//!
//! Analyzes input data to determine if neural compression is appropriate
//! and which model preset to use.

mod classifier;

pub use classifier::{ContentClassifier, ContentType, SuitabilityScore};
