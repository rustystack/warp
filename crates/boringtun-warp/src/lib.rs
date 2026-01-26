#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(clippy::borrow_deref_ref)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::redundant_guards)]

//! boringtun-warp: WireGuard implementation for WARP
//!
//! This is a fork of Cloudflare's boringtun with updated stable dependencies
//! that are compatible with the WARP project's cryptography stack.
//!
//! # Key Changes from boringtun 0.7.0
//!
//! - `chacha20poly1305`: Updated from `0.10.0-pre.1` to stable `0.10`
//! - `aead`: Updated from `0.5.0-pre.2` to stable `0.5`
//! - `base64`: Updated from `0.13` to `0.22`
//! - Removed `ring` dependency in favor of `blake2` + `hmac` for HKDF
//!
//! # Example
//!
//! ```rust,no_run
//! use boringtun_warp::noise::{Tunn, TunnResult};
//! use boringtun_warp::x25519::{StaticSecret, PublicKey};
//! use rand_core::OsRng;
//!
//! // Generate keypairs
//! let my_secret = StaticSecret::random_from_rng(OsRng);
//! let my_public = PublicKey::from(&my_secret);
//!
//! let peer_secret = StaticSecret::random_from_rng(OsRng);
//! let peer_public = PublicKey::from(&peer_secret);
//!
//! // Create tunnel
//! let mut tunnel = Tunn::new(
//!     my_secret,
//!     peer_public,
//!     None, // preshared key
//!     None, // persistent keepalive
//!     0,    // tunnel index
//! ).unwrap();
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod noise;

/// Re-export x25519-dalek types for convenience
pub mod x25519 {
    pub use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
}

/// Prelude module with commonly used types
pub mod prelude {
    pub use crate::noise::{Tunn, TunnResult};
    pub use crate::x25519::{PublicKey, StaticSecret};
}
