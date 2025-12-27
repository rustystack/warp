//! Deduplication Registry for Chonkers
//!
//! Provides reference-counted chunk storage with garbage collection
//! for efficient versioned deduplication.
//!
//! # Components
//!
//! - **ChunkRegistry**: Central registry for chunk metadata and reference counting
//! - **ChunkStore**: Trait for chunk data storage backends
//! - **GarbageCollector**: Configurable GC for cleaning up unreferenced chunks
//!
//! # Usage
//!
//! ```rust,ignore
//! use warp_chonkers::dedup::{ChunkRegistry, MemoryChunkStore, GarbageCollector, GcConfig};
//! use std::sync::Arc;
//!
//! // Create registry with memory storage
//! let registry = ChunkRegistry::in_memory();
//!
//! // Register chunks from a version
//! let version = VersionId::new(1);
//! for chunk in chunks {
//!     registry.register(chunk.id, &chunk_data, chunk.weight, version)?;
//! }
//!
//! // Later, unregister a version
//! registry.unregister_version(version)?;
//!
//! // Run garbage collection
//! let gc = GarbageCollector::with_defaults(Arc::new(registry));
//! let stats = gc.collect()?;
//! println!("Freed {} bytes", stats.bytes_freed);
//! ```

mod gc;
mod registry;

pub use gc::{GarbageCollector, GcConfig, GcEvent, GcEventHandler, LoggingGcHandler};
pub use registry::{ChunkMetadata, ChunkRegistry, ChunkStore, GcStats, MemoryChunkStore};
