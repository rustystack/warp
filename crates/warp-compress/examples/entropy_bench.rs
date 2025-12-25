use std::time::Instant;
use rayon::prelude::*;

fn calculate_entropy_scalar(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy / 8.0
}

fn calculate_entropy_parallel(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    
    let freq: [u64; 256] = data.par_chunks(16 * 1024)
        .map(|chunk| {
            let mut local_freq = [0u64; 256];
            for &byte in chunk {
                local_freq[byte as usize] += 1;
            }
            local_freq
        })
        .reduce(
            || [0u64; 256],
            |mut acc, local| {
                for i in 0..256 { acc[i] += local[i]; }
                acc
            },
        );
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy / 8.0
}

fn main() {
    let sizes = [
        (64 * 1024, "64KB"),
        (256 * 1024, "256KB"),
        (1024 * 1024, "1MB"),
        (10 * 1024 * 1024, "10MB"),
        (100 * 1024 * 1024, "100MB"),
    ];
    
    println!("Entropy Calculation Benchmark");
    println!("=============================\n");
    println!("{:>8} | {:>12} | {:>12} | {:>8}", "Size", "Scalar", "Parallel", "Speedup");
    println!("{:-<8}-+-{:-<12}-+-{:-<12}-+-{:-<8}", "", "", "", "");
    
    for (size, name) in sizes {
        let data: Vec<u8> = (0..size).map(|i| ((i * 17 + 31) % 256) as u8).collect();
        
        // Warmup
        let _ = calculate_entropy_scalar(&data);
        let _ = calculate_entropy_parallel(&data);
        
        let iterations = if size < 1024 * 1024 { 100 } else { 10 };
        
        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(calculate_entropy_scalar(&data));
        }
        let scalar_time = start.elapsed().as_nanos() as f64 / iterations as f64;
        
        let start = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(calculate_entropy_parallel(&data));
        }
        let parallel_time = start.elapsed().as_nanos() as f64 / iterations as f64;
        
        let speedup = scalar_time / parallel_time;
        let scalar_gbps = (size as f64 / scalar_time) * 1e9 / (1024.0 * 1024.0 * 1024.0);
        let parallel_gbps = (size as f64 / parallel_time) * 1e9 / (1024.0 * 1024.0 * 1024.0);
        
        println!("{:>8} | {:>9.2} GB/s | {:>9.2} GB/s | {:>7.2}x", 
            name, scalar_gbps, parallel_gbps, speedup);
    }
}
