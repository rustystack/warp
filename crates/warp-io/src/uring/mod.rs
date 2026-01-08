//! io_uring backend for high-performance Linux I/O
//!
//! This module provides native io_uring support for 2-5x IOPS improvement
//! over epoll/kqueue-based async I/O on Linux systems.
//!
//! # Features
//!
//! - Native io_uring kernel interface
//! - Registered buffers for zero-copy operations
//! - Kernel-side polling (SQPOLL) for lowest latency
//! - Batched I/O operations
//!
//! # Platform Support
//!
//! This module is only available on Linux systems with kernel 5.1+.
//! On other platforms, use the standard tokio async I/O fallback.

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod async_io;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod backend;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod registered_buffers;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use async_io::{IoUringAsyncReader, IoUringChunker, chunk_file_uring};
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use backend::{IoUringBackend, IoUringStats};
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use registered_buffers::{RegisteredBuffer, RegisteredBufferPool};

/// io_uring configuration options
#[derive(Debug, Clone)]
pub struct IoUringConfig {
    /// Number of submission queue entries (power of 2, default: 256)
    pub sq_entries: u32,
    /// Enable kernel-side polling for lowest latency (default: true)
    pub enable_sqpoll: bool,
    /// SQPOLL idle timeout in milliseconds (default: 1000)
    pub sqpoll_idle_ms: u32,
    /// Number of registered buffers for zero-copy (default: 64)
    pub num_registered_buffers: usize,
    /// Size of each registered buffer (default: 64KB)
    pub buffer_size: usize,
}

impl Default for IoUringConfig {
    fn default() -> Self {
        Self {
            sq_entries: 256,
            enable_sqpoll: true,
            sqpoll_idle_ms: 1000,
            num_registered_buffers: 64,
            buffer_size: 64 * 1024, // 64KB
        }
    }
}

impl IoUringConfig {
    /// Create config optimized for high-throughput bulk transfers
    pub fn bulk_transfer() -> Self {
        Self {
            sq_entries: 512,
            enable_sqpoll: true,
            sqpoll_idle_ms: 2000,
            num_registered_buffers: 128,
            buffer_size: 256 * 1024, // 256KB
        }
    }

    /// Create config optimized for low-latency small I/O
    pub fn low_latency() -> Self {
        Self {
            sq_entries: 128,
            enable_sqpoll: true,
            sqpoll_idle_ms: 500,
            num_registered_buffers: 256,
            buffer_size: 4 * 1024, // 4KB
        }
    }

    /// Create config for memory-constrained environments
    pub fn minimal() -> Self {
        Self {
            sq_entries: 64,
            enable_sqpoll: false,
            sqpoll_idle_ms: 0,
            num_registered_buffers: 16,
            buffer_size: 16 * 1024, // 16KB
        }
    }
}

/// Check if io_uring is available on the current system
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub fn is_available() -> bool {
    // Check kernel version >= 5.1 by reading /proc/version
    if let Ok(version_str) = std::fs::read_to_string("/proc/version") {
        if let Some(version) = parse_kernel_version(&version_str) {
            return version >= (5, 1, 0);
        }
    }
    false
}

#[cfg(not(all(target_os = "linux", feature = "io-uring")))]
pub fn is_available() -> bool {
    false
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
fn parse_kernel_version(version_str: &str) -> Option<(u32, u32, u32)> {
    // /proc/version format: "Linux version X.Y.Z-..."
    // Extract the version number part
    let version_part = version_str.split_whitespace().find(|s| {
        s.chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
    })?;

    let parts: Vec<&str> = version_part.split('.').collect();
    if parts.len() >= 2 {
        let major = parts[0].parse().ok()?;
        let minor_part = parts[1].split('-').next()?;
        let minor = minor_part.parse().ok()?;
        let patch = if parts.len() >= 3 {
            parts[2].split('-').next()?.parse().unwrap_or(0)
        } else {
            0
        };
        return Some((major, minor, patch));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = IoUringConfig::default();
        assert_eq!(config.sq_entries, 256);
        assert!(config.enable_sqpoll);
        assert_eq!(config.num_registered_buffers, 64);
    }

    #[test]
    fn test_config_presets() {
        let bulk = IoUringConfig::bulk_transfer();
        assert_eq!(bulk.sq_entries, 512);
        assert_eq!(bulk.buffer_size, 256 * 1024);

        let low_lat = IoUringConfig::low_latency();
        assert_eq!(low_lat.buffer_size, 4 * 1024);

        let minimal = IoUringConfig::minimal();
        assert!(!minimal.enable_sqpoll);
    }

    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    #[test]
    fn test_kernel_version_parsing() {
        // Test /proc/version format
        assert_eq!(
            parse_kernel_version("Linux version 5.15.0-generic (buildd@host) ..."),
            Some((5, 15, 0))
        );
        assert_eq!(
            parse_kernel_version("Linux version 6.1.0 (root@build)"),
            Some((6, 1, 0))
        );
        assert_eq!(
            parse_kernel_version("Linux version 4.19.123-custom (user@machine)"),
            Some((4, 19, 123))
        );
    }

    #[test]
    fn test_availability_check() {
        // This should not panic regardless of platform
        let _ = is_available();
    }
}
