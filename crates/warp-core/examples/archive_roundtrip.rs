//! Warp archive creation and extraction example
//!
//! Demonstrates creating and reading .warp archive files
//! with compression and integrity verification.
//!
//! Run with: cargo run -p warp-core --example archive_roundtrip

use std::fs;
use tempfile::TempDir;
use warp_format::{WarpWriter, WarpReader, WarpWriterConfig};

fn main() {
    println!("=== Warp Archive Demo ===\n");

    // Create temporary directories
    let temp = TempDir::new().expect("Failed to create temp dir");
    let source_dir = temp.path().join("source");
    let extract_dir = temp.path().join("extracted");
    let archive_path = temp.path().join("demo.warp");

    // Create sample directory structure
    fs::create_dir_all(&source_dir).unwrap();
    fs::create_dir_all(source_dir.join("subdir")).unwrap();

    fs::write(source_dir.join("readme.txt"), "Hello from Warp!").unwrap();
    fs::write(source_dir.join("data.bin"), vec![0xAB; 10000]).unwrap();
    fs::write(source_dir.join("subdir/nested.txt"), "Nested file content").unwrap();

    println!("Source directory structure:");
    println!("  source/");
    println!("    readme.txt (16 bytes)");
    println!("    data.bin (10000 bytes)");
    println!("    subdir/");
    println!("      nested.txt (19 bytes)");

    // Create archive with Zstd compression
    println!("\nCreating archive with Zstd compression...");
    let config = WarpWriterConfig::with_zstd();
    let mut writer = WarpWriter::create_with_config(&archive_path, config)
        .expect("Failed to create writer");

    writer.add_directory(&source_dir, "")
        .expect("Failed to add directory");

    writer.finish().expect("Failed to finalize archive");

    let archive_size = fs::metadata(&archive_path).unwrap().len();
    println!("Archive created: {:?}", archive_path);
    println!("  Archive size: {} bytes", archive_size);

    // Read and extract archive
    println!("\nOpening archive...");
    fs::create_dir_all(&extract_dir).unwrap();

    let reader = WarpReader::open(&archive_path)
        .expect("Failed to open archive");

    println!("Archive info:");
    println!("  Encrypted: {}", reader.is_encrypted());
    println!("  File count: {}", reader.file_count());
    println!("  Chunk count: {}", reader.chunk_count());

    // List entries
    println!("\nArchive contents:");
    for entry in reader.list_files() {
        println!("  {} ({} bytes)",
                 entry.path,
                 entry.size);
    }

    // Get stats
    let (original, compressed, ratio) = reader.stats();
    println!("\nStatistics:");
    println!("  Original size: {} bytes", original);
    println!("  Compressed size: {} bytes", compressed);
    println!("  Compression ratio: {:.2}x", ratio);

    // Verify integrity
    println!("\nVerifying integrity...");
    let valid = reader.verify().expect("Verification failed");
    println!("  Merkle verification: {}", if valid { "PASSED" } else { "FAILED" });

    // Extract all files
    println!("\nExtracting files...");
    reader.extract_all(&extract_dir).expect("Extraction failed");

    // Verify extracted content
    println!("\nVerifying extracted files...");

    let readme = fs::read_to_string(extract_dir.join("readme.txt")).unwrap();
    assert_eq!(readme, "Hello from Warp!");
    println!("  readme.txt: OK");

    let data = fs::read(extract_dir.join("data.bin")).unwrap();
    assert_eq!(data, vec![0xAB; 10000]);
    println!("  data.bin: OK");

    let nested = fs::read_to_string(extract_dir.join("subdir/nested.txt")).unwrap();
    assert_eq!(nested, "Nested file content");
    println!("  subdir/nested.txt: OK");

    println!("\nAll files verified successfully!");
}
