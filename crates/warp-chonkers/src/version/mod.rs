//! Version Management for Chonkers
//!
//! Provides versioned data management with efficient delta computation
//! and time-travel capabilities.
//!
//! # Components
//!
//! - **Delta**: Represents the difference between two versions
//! - **VersionTimeline**: Manages version history with commits, checkouts, and refs
//! - **DeltaBuilder**: Configurable delta computation
//!
//! # Usage
//!
//! ```rust,ignore
//! use warp_chonkers::{ChonkersConfig, ChunkRegistry, VersionTimeline};
//! use warp_chonkers::tree::MemoryTreeStore;
//! use warp_chonkers::dedup::MemoryChunkStore;
//! use std::sync::Arc;
//!
//! // Create timeline
//! let config = ChonkersConfig::default();
//! let store = Arc::new(MemoryChunkStore::new());
//! let registry = Arc::new(ChunkRegistry::with_store(store));
//! let tree_store = Arc::new(MemoryTreeStore::new());
//! let timeline = VersionTimeline::new(config, registry, tree_store);
//!
//! // Commit versions
//! let v1 = timeline.commit(b"version 1 data", Some("Initial commit"))?;
//! let v2 = timeline.commit(b"version 2 data", Some("Update"))?;
//!
//! // Create references
//! timeline.create_ref("main", v2);
//!
//! // Compute delta
//! let delta = timeline.delta(v1, v2)?;
//! println!("Changes: {} added, {} removed", delta.added.len(), delta.removed.len());
//!
//! // Time travel
//! let old_tree = timeline.checkout(v1)?;
//! ```

mod delta;
mod timeline;

pub use delta::{Delta, DeltaBuilder, DeltaStats, ChunkMove};
pub use timeline::{TimelineBuilder, VersionInfo, VersionTimeline};
