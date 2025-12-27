//! Model loading and session management
//!
//! This module handles ONNX model loading, caching, and session management
//! for neural compression inference.

mod presets;
mod session;

pub use presets::{ModelConfig, ModelPreset};
pub use session::{ModelResolver, SessionCache};
