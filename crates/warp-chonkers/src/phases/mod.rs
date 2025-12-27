//! Three-phase processing for the Chonkers algorithm
//!
//! Each layer is processed through three phases:
//!
//! 1. **Balancing**: Finds "kittens" (chunks lighter than both neighbors)
//!    and merges them with their lighter neighbor.
//!
//! 2. **Caterpillar**: Detects periodic repetitions using Z-algorithm
//!    and collapses them into single chunks.
//!
//! 3. **Diffbit**: Uses XOR of boundary bytes for priority-based merging
//!    to achieve final chunk boundaries.

mod balancing;
mod caterpillar;
mod diffbit;

pub use balancing::BalancingPhase;
pub use caterpillar::CaterpillarPhase;
pub use diffbit::DiffbitPhase;
