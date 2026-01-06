//! info command - display local system capabilities
//!
//! Shows information about the local system including CPU, GPU, compression
//! algorithms, network capabilities, and configuration paths.

use anyhow::Result;
use warp_core::Session;

/// Execute the info command
///
/// Displays comprehensive system information including:
/// - CPU cores
/// - GPU availability and details (if compiled with gpu feature)
/// - Compression algorithms
/// - Network transport
/// - Configuration paths
pub async fn execute() -> Result<()> {
    println!("warp - System Information");
    println!("{}", "=".repeat(60));
    println!();

    // CPU information
    display_cpu_info();

    // GPU information
    display_gpu_info();

    // Compression information
    display_compression_info();

    // Network information
    display_network_info();

    // Paths information
    display_paths_info();

    // Version information
    display_version_info();

    Ok(())
}

/// Display CPU information
fn display_cpu_info() {
    println!("CPU");
    println!("{}", "-".repeat(60));

    let cores = num_cpus();
    println!("  Physical Cores:  {}", cores);

    // Try to get more detailed info
    #[cfg(target_os = "linux")]
    {
        if let Ok(info) = std::fs::read_to_string("/proc/cpuinfo") {
            if let Some(model) = extract_cpu_model(&info) {
                println!("  Model:           {}", model);
            }
        }
    }

    println!();
}

/// Display GPU information
fn display_gpu_info() {
    println!("GPU");
    println!("{}", "-".repeat(60));

    #[cfg(feature = "gpu")]
    {
        match detect_gpu_info() {
            Some(info) => {
                println!("  Status:          Available");
                println!("  Device:          {}", info.name);
                println!(
                    "  Memory:          {:.2} GB",
                    info.memory as f64 / 1024.0 / 1024.0 / 1024.0
                );
                println!(
                    "  Compute:         {}.{}",
                    info.compute_major, info.compute_minor
                );
                println!("  Driver:          CUDA");
            }
            None => {
                println!("  Status:          Not available");
                println!("  Reason:          Initialization failed or no CUDA device found");
            }
        }
    }

    #[cfg(not(feature = "gpu"))]
    {
        println!("  Status:          Not compiled");
        println!("  Note:            Rebuild with --features gpu to enable");
    }

    println!();
}

/// Display compression information
fn display_compression_info() {
    println!("Compression");
    println!("{}", "-".repeat(60));

    println!("  CPU Algorithms:");
    println!("    - zstd:        Levels 1-22 (default: 3)");
    println!("    - lz4:         Fast compression");
    println!();

    #[cfg(feature = "gpu")]
    {
        println!("  GPU Acceleration:");
        match detect_gpu_info() {
            Some(_) => {
                println!("    - Status:      Available");
                println!("    - Algorithms:  zstd, lz4");
                println!("    - Batch Mode:  Supported");
            }
            None => {
                println!("    - Status:      Unavailable (GPU not initialized)");
            }
        }
        println!();
    }

    #[cfg(not(feature = "gpu"))]
    {
        println!("  GPU Acceleration:");
        println!("    - Status:      Not compiled");
        println!();
    }
}

/// Display network information
fn display_network_info() {
    println!("Network");
    println!("{}", "-".repeat(60));
    println!("  Transport:       QUIC (UDP-based)");
    println!("  Security:        TLS 1.3");
    println!("  Max Streams:     Up to 256 concurrent");
    println!("  Default Streams: 16 parallel");
    println!("  Chunk Size:      4 MB (configurable)");
    println!();
}

/// Display paths information
fn display_paths_info() {
    println!("Paths");
    println!("{}", "-".repeat(60));

    let sessions_dir = Session::sessions_dir();
    println!("  Sessions:        {}", sessions_dir.display());

    // Check if sessions directory exists and count sessions
    if sessions_dir.exists() {
        match Session::list(&sessions_dir) {
            Ok(sessions) => {
                println!("  Saved Sessions:  {}", sessions.len());
            }
            Err(_) => {
                println!("  Saved Sessions:  0");
            }
        }
    } else {
        println!("  Saved Sessions:  0 (directory not created)");
    }

    // Display config directory
    if let Some(config_dir) = dirs::config_dir() {
        let warp_config = config_dir.join("warp");
        println!("  Config:          {}", warp_config.display());
    }

    // Display cache directory
    if let Some(cache_dir) = dirs::cache_dir() {
        let warp_cache = cache_dir.join("warp");
        println!("  Cache:           {}", warp_cache.display());
    }

    println!();
}

/// Display version information
fn display_version_info() {
    println!("Version");
    println!("{}", "-".repeat(60));
    println!("  warp:            {}", env!("CARGO_PKG_VERSION"));
    println!("  Protocol:        1");
    println!("  Edition:         2024");
    println!("  Rust Version:    {}", env!("CARGO_PKG_RUST_VERSION"));
    println!();
}

/// Get the number of CPU cores
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

/// Extract CPU model name from /proc/cpuinfo
#[cfg(target_os = "linux")]
fn extract_cpu_model(cpuinfo: &str) -> Option<String> {
    for line in cpuinfo.lines() {
        if line.starts_with("model name") {
            if let Some(colon_pos) = line.find(':') {
                let model = line[colon_pos + 1..].trim();
                return Some(model.to_string());
            }
        }
    }
    None
}

/// GPU information structure
#[cfg(feature = "gpu")]
struct GpuInfo {
    name: String,
    memory: usize,
    compute_major: i32,
    compute_minor: i32,
}

/// Detect GPU information
#[cfg(feature = "gpu")]
fn detect_gpu_info() -> Option<GpuInfo> {
    use warp_compress::GpuContext;

    match GpuContext::new() {
        Ok(ctx) => {
            let name = ctx
                .device_name()
                .unwrap_or_else(|_| "Unknown GPU".to_string());
            let memory = ctx.total_memory();
            let (compute_major, compute_minor) = ctx.capabilities().compute_capability;

            Some(GpuInfo {
                name,
                memory,
                compute_major,
                compute_minor,
            })
        }
        Err(e) => {
            tracing::debug!("GPU detection failed: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num_cpus() {
        let cores = num_cpus();
        assert!(cores > 0);
        assert!(cores <= 1024); // Sanity check
    }

    #[tokio::test]
    async fn test_execute() {
        let result = execute().await;
        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_extract_cpu_model() {
        let cpuinfo = "processor\t: 0\nmodel name\t: Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz\n";
        let model = extract_cpu_model(cpuinfo);
        assert_eq!(
            model,
            Some("Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz".to_string())
        );
    }

    #[cfg(feature = "gpu")]
    #[test]
    fn test_detect_gpu_info() {
        // This may fail if no GPU is available, which is OK
        let _info = detect_gpu_info();
    }
}
