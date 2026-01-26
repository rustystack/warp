//! Conflict-free Replicated Data Types (CRDTs) for warp distributed storage
//!
//! This crate provides CRDTs for conflict-free geo-replication, enabling
//! multi-site active-active writes without coordination overhead.
//!
//! # Key Components
//!
//! - **HLC (Hybrid Logical Clock)**: Physical + logical time for distributed ordering
//! - **LWWRegister**: Last-Write-Wins register for single values
//! - **ORSet**: Observed-Remove Set for collection operations
//! - **GCounter/PNCounter**: Grow-only and positive-negative counters
//!
//! # CRDT Properties
//!
//! All CRDTs in this crate satisfy the following properties:
//! - **Commutativity**: `a.merge(b) == b.merge(a)`
//! - **Associativity**: `a.merge(b.merge(c)) == (a.merge(b)).merge(c)`
//! - **Idempotency**: `a.merge(a) == a`
//!
//! These properties ensure eventual consistency without coordination.
//!
//! # Example
//!
//! ```rust,ignore
//! use warp_crdt::{HLC, LWWRegister, ORSet};
//!
//! // Create clocks for two nodes
//! let mut clock_a = HLC::new(1);
//! let mut clock_b = HLC::new(2);
//!
//! // Concurrent writes with LWWRegister
//! let mut reg_a = LWWRegister::new("value_a".to_string(), &mut clock_a);
//! let mut reg_b = LWWRegister::new("value_b".to_string(), &mut clock_b);
//!
//! // Merge converges to same value on both nodes
//! reg_a.merge(&reg_b, &mut clock_a);
//! reg_b.merge(&reg_a, &mut clock_b);
//! assert_eq!(reg_a.get(), reg_b.get());
//!
//! // ORSet for collections
//! let mut set_a = ORSet::new(1);
//! set_a.add("item1");
//! set_a.add("item2");
//!
//! let mut set_b = ORSet::new(2);
//! set_b.add("item3");
//! set_b.remove(&"item1"); // Concurrent with add on node A
//!
//! // After merge, add-wins semantics apply
//! set_a.merge(&set_b);
//! ```

#![warn(missing_docs)]
#![allow(clippy::match_like_matches_macro)]

pub mod g_counter;
pub mod hlc;
pub mod lww_register;
pub mod merge;
pub mod or_set;
pub mod pn_counter;

pub use g_counter::GCounter;
pub use hlc::HLC;
pub use lww_register::LWWRegister;
pub use merge::{CrdtMerge, MergeStats};
pub use or_set::{Dot, ORSet};
pub use pn_counter::PNCounter;

use thiserror::Error;

/// CRDT error types
#[derive(Debug, Error)]
pub enum CrdtError {
    /// Clock drift detected (physical time went backwards)
    #[error("Clock drift detected: expected >= {expected}, got {actual}")]
    ClockDrift {
        /// Expected minimum time
        expected: u64,
        /// Actual time observed
        actual: u64,
    },

    /// Node ID mismatch during operation
    #[error("Node ID mismatch: expected {expected}, got {actual}")]
    NodeIdMismatch {
        /// Expected node ID
        expected: u64,
        /// Actual node ID
        actual: u64,
    },

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid state
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

/// Result type for CRDT operations
pub type Result<T> = std::result::Result<T, CrdtError>;

/// Node identifier type (64-bit)
pub type NodeId = u64;

/// Logical counter type
pub type Counter = u64;
