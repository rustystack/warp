//! Neural compression implementations
//!
//! Provides `WallocCompressor` for WaLLoC neural compression and
//! `AdaptiveNeuralCompressor` for automatic algorithm selection.

mod adaptive;
mod batch;
mod walloc;

pub use adaptive::AdaptiveNeuralCompressor;
pub use batch::BatchNeuralCompressor;
pub use walloc::{QualityConfig, WallocCompressor};
