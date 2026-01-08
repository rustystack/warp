//! bench command - benchmark transfer performance
//!
//! This command provides comprehensive benchmarking capabilities for testing
//! compression algorithms and network transfer performance.

use anyhow::{Context, Result};
use bytes::Bytes;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use warp_net::WarpEndpoint;

/// Execute the bench command
///
/// # Arguments
/// * `server` - Server address to benchmark, or "local" for local compression benchmark
/// * `size` - Size of test data (e.g., "1G", "100M", "10M")
///
/// # Errors
/// Returns an error if:
/// - Size format is invalid
/// - Connection to server fails (for remote benchmarks)
/// - Benchmark execution fails
pub async fn execute(server: &str, size: &str) -> Result<()> {
    println!("warp - Performance Benchmark");
    println!("{}", "=".repeat(60));
    println!();

    // Parse size
    let bytes = parse_size(size).context("Invalid size format")?;

    // Check if local or remote benchmark
    if server.eq_ignore_ascii_case("local") {
        run_local_benchmark(bytes).await
    } else {
        run_remote_benchmark(server, bytes).await
    }
}

/// Parse size string (e.g., "1G", "100M", "10M") to bytes
fn parse_size(size: &str) -> Result<u64> {
    let size = size.trim().to_uppercase();

    // Handle plain numbers (assume bytes)
    if let Ok(num) = size.parse::<u64>() {
        return Ok(num);
    }

    // Find where digits end and suffix begins
    let split_pos = size
        .chars()
        .position(|c| !c.is_ascii_digit())
        .ok_or_else(|| anyhow::anyhow!("Invalid size format"))?;

    let (num_str, suffix) = size.split_at(split_pos);
    let num: u64 = num_str.parse().context("Invalid numeric value in size")?;

    let multiplier = match suffix {
        "B" => 1,
        "K" | "KB" => 1024,
        "M" | "MB" => 1024 * 1024,
        "G" | "GB" => 1024 * 1024 * 1024,
        "T" | "TB" => 1024 * 1024 * 1024 * 1024,
        _ => anyhow::bail!(
            "Invalid size suffix '{}'. Use B, K/KB, M/MB, G/GB, or T/TB",
            suffix
        ),
    };

    Ok(num * multiplier)
}

/// Run local compression benchmark
async fn run_local_benchmark(bytes: u64) -> Result<()> {
    println!("Mode:     Local compression benchmark");
    println!("Size:     {}", format_bytes(bytes));
    println!();

    // Generate random test data
    let pb = ProgressBar::new_spinner();
    pb.set_message("Generating random test data...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let data = generate_random_data(bytes as usize);
    pb.finish_and_clear();

    println!("Test data generated: {} bytes", data.len());
    println!();

    // Benchmark compression algorithms
    println!("Compression Benchmarks");
    println!("{}", "-".repeat(60));

    // Zstd
    let (zstd_ratio, zstd_speed, zstd_time) = bench_compression(&data, "zstd")?;
    println!(
        "zstd:     {:.2}% reduction, {}/s, {:.2}s total",
        (1.0 - zstd_ratio) * 100.0,
        format_bytes(zstd_speed),
        zstd_time
    );

    // LZ4
    let (lz4_ratio, lz4_speed, lz4_time) = bench_compression(&data, "lz4")?;
    println!(
        "lz4:      {:.2}% reduction, {}/s, {:.2}s total",
        (1.0 - lz4_ratio) * 100.0,
        format_bytes(lz4_speed),
        lz4_time
    );

    println!();

    // GPU benchmark if available
    #[cfg(feature = "gpu")]
    {
        if let Some(gpu_results) = bench_gpu_compression(&data).await {
            println!("GPU Compression Benchmarks");
            println!("{}", "-".repeat(60));
            println!(
                "GPU zstd: {:.2}% reduction, {}/s, {:.2}s total",
                (1.0 - gpu_results.zstd_ratio) * 100.0,
                format_bytes(gpu_results.zstd_speed),
                gpu_results.zstd_time
            );
            println!(
                "GPU lz4:  {:.2}% reduction, {}/s, {:.2}s total",
                (1.0 - gpu_results.lz4_ratio) * 100.0,
                format_bytes(gpu_results.lz4_speed),
                gpu_results.lz4_time
            );
            println!();
        }
    }

    println!("Benchmark completed successfully");
    Ok(())
}

/// Run remote transfer benchmark
async fn run_remote_benchmark(server: &str, bytes: u64) -> Result<()> {
    println!("Mode:     Remote transfer benchmark");
    println!("Server:   {}", server);
    println!("Size:     {}", format_bytes(bytes));
    println!();

    // Parse address
    let addr: SocketAddr = server
        .parse()
        .context("Invalid server address. Expected format: host:port")?;

    // Connect and measure
    print!("Connecting to server... ");
    std::io::Write::flush(&mut std::io::stdout()).ok();

    let start = Instant::now();
    let endpoint = WarpEndpoint::client()
        .await
        .context("Failed to create endpoint")?;

    let conn = endpoint
        .connect(addr, "warp-server")
        .await
        .context("Failed to connect to server")?;

    let _params = conn.handshake().await.context("Handshake failed")?;

    let connect_time = start.elapsed();
    println!("OK ({:.2}ms)", connect_time.as_secs_f64() * 1000.0);

    // Generate test data
    println!();
    let pb = ProgressBar::new_spinner();
    pb.set_message("Generating test data...");
    pb.enable_steady_tick(Duration::from_millis(100));

    let data = generate_random_data(bytes as usize);
    pb.finish_and_clear();

    // Send data in chunks
    println!("Transferring data...");
    let chunk_size = 1024 * 1024; // 1MB chunks
    let chunks: Vec<_> = data.chunks(chunk_size).collect();

    let pb = ProgressBar::new(chunks.len() as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} chunks | {msg}",
        )
        .unwrap()
        .progress_chars("#>-"),
    );

    let transfer_start = Instant::now();

    for (i, chunk) in chunks.iter().enumerate() {
        conn.send_chunk(i as u32, Bytes::copy_from_slice(chunk))
            .await
            .context("Failed to send chunk")?;

        pb.inc(1);

        let elapsed = transfer_start.elapsed().as_secs_f64();
        let transferred = (i + 1) * chunk_size;
        let speed = transferred as f64 / elapsed;
        pb.set_message(format!("{}/s", format_bytes(speed as u64)));
    }

    let transfer_time = transfer_start.elapsed();
    let total_time = start.elapsed();
    pb.finish_and_clear();

    // Calculate metrics
    let throughput = bytes as f64 / transfer_time.as_secs_f64();

    println!();
    println!("Results");
    println!("{}", "-".repeat(60));
    println!(
        "Connect Time:     {:.2} ms",
        connect_time.as_secs_f64() * 1000.0
    );
    println!("Transfer Time:    {:.2} s", transfer_time.as_secs_f64());
    println!("Total Time:       {:.2} s", total_time.as_secs_f64());
    println!("Throughput:       {}/s", format_bytes(throughput as u64));
    println!(
        "Average Latency:  {:.2} ms/chunk",
        transfer_time.as_secs_f64() * 1000.0 / chunks.len() as f64
    );

    // Close connection
    conn.close().await.ok();

    println!();
    println!("Benchmark completed successfully");

    Ok(())
}

/// Generate random data for benchmarking
fn generate_random_data(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; size];

    // Fill with random data
    rng.fill(&mut data[..]);

    data
}

/// Benchmark CPU compression
fn bench_compression(data: &[u8], algo: &str) -> Result<(f64, u64, f64)> {
    use warp_compress::{Compressor, Lz4Compressor, ZstdCompressor};

    let compressor: Box<dyn Compressor> = match algo {
        "zstd" => Box::new(ZstdCompressor::default()),
        "lz4" => Box::new(Lz4Compressor::new()),
        _ => anyhow::bail!("Unknown compression algorithm: {}", algo),
    };

    let start = Instant::now();
    let compressed = compressor.compress(data).context("Compression failed")?;
    let elapsed = start.elapsed();

    let ratio = compressed.len() as f64 / data.len() as f64;
    let speed = (data.len() as f64 / elapsed.as_secs_f64()) as u64;
    let time = elapsed.as_secs_f64();

    Ok((ratio, speed, time))
}

/// GPU benchmark results
#[cfg(feature = "gpu")]
struct GpuBenchResults {
    zstd_ratio: f64,
    zstd_speed: u64,
    zstd_time: f64,
    lz4_ratio: f64,
    lz4_speed: u64,
    lz4_time: f64,
}

/// Benchmark GPU compression
#[cfg(feature = "gpu")]
async fn bench_gpu_compression(data: &[u8]) -> Option<GpuBenchResults> {
    use warp_compress::gpu::PinnedMemoryPool;
    use warp_compress::{Compressor, GpuContext, GpuLz4Compressor, GpuZstdCompressor};

    let ctx = match GpuContext::new() {
        Ok(ctx) => ctx,
        Err(e) => {
            tracing::debug!("GPU not available: {}", e);
            return None;
        }
    };

    let context = std::sync::Arc::new(ctx);
    let memory_pool =
        std::sync::Arc::new(PinnedMemoryPool::with_defaults(context.context().clone()));

    // Zstd
    let zstd_compressor =
        match GpuZstdCompressor::with_context_and_level(context.clone(), memory_pool.clone(), 3) {
            Ok(c) => c,
            Err(_) => return None,
        };

    let start = Instant::now();
    let compressed = match zstd_compressor.compress(data) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let elapsed = start.elapsed();

    let zstd_ratio = compressed.len() as f64 / data.len() as f64;
    let zstd_speed = (data.len() as f64 / elapsed.as_secs_f64()) as u64;
    let zstd_time = elapsed.as_secs_f64();

    // LZ4
    let lz4_compressor = match GpuLz4Compressor::with_context(context.clone()) {
        Ok(c) => c,
        Err(_) => return None,
    };

    let start = Instant::now();
    let compressed = match lz4_compressor.compress(data) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let elapsed = start.elapsed();

    let lz4_ratio = compressed.len() as f64 / data.len() as f64;
    let lz4_speed = (data.len() as f64 / elapsed.as_secs_f64()) as u64;
    let lz4_time = elapsed.as_secs_f64();

    Some(GpuBenchResults {
        zstd_ratio,
        zstd_speed,
        zstd_time,
        lz4_ratio,
        lz4_speed,
        lz4_time,
    })
}

/// Format bytes into human-readable format
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", size as u64, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("100M").unwrap(), 100 * 1024 * 1024);

        assert!(parse_size("invalid").is_err());
        assert!(parse_size("1X").is_err());
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1536 * 1024), "1.50 MB");
    }

    #[test]
    fn test_generate_random_data() {
        let data = generate_random_data(1024);
        assert_eq!(data.len(), 1024);

        // Check that data is not all zeros (very unlikely with random data)
        let sum: u64 = data.iter().map(|&b| b as u64).sum();
        assert!(sum > 0);
    }

    #[test]
    fn test_bench_compression_zstd() {
        let data = generate_random_data(10 * 1024); // 10KB
        let result = bench_compression(&data, "zstd");
        assert!(result.is_ok());

        let (ratio, speed, time) = result.unwrap();
        // Random data may not compress well (ratio can be > 1.0)
        assert!(ratio > 0.0);
        assert!(speed > 0);
        assert!(time > 0.0);
    }

    #[test]
    fn test_bench_compression_lz4() {
        let data = generate_random_data(10 * 1024); // 10KB
        let result = bench_compression(&data, "lz4");
        assert!(result.is_ok());

        let (ratio, speed, time) = result.unwrap();
        // Random data may not compress well (ratio can be > 1.0)
        assert!(ratio > 0.0);
        assert!(speed > 0);
        assert!(time > 0.0);
    }

    #[test]
    fn test_bench_compression_invalid() {
        let data = generate_random_data(1024);
        let result = bench_compression(&data, "invalid");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_local_benchmark_small() {
        // Test with small size to keep test fast
        let result = run_local_benchmark(1024).await;
        assert!(result.is_ok());
    }
}
