//! Payload analysis for optimal transfer strategy

use crate::Result;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use warp_compress::adaptive::calculate_entropy;
use warp_io::walk_directory;

/// Payload analysis results
#[derive(Debug, Clone)]
pub struct PayloadAnalysis {
    /// Total size in bytes
    pub total_size: u64,
    /// Number of files
    pub file_count: usize,
    /// Average entropy (0.0 = compressible, 1.0 = random)
    pub avg_entropy: f64,
    /// Recommended compression strategy
    pub compression_hint: CompressionHint,
    /// Recommended chunk size
    pub chunk_size_hint: u32,
    /// File type distribution
    pub file_types: HashMap<String, usize>,
}

/// Compression strategy hint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionHint {
    /// Data is highly compressible (text, JSON, etc.)
    HighlyCompressible,
    /// Data is already compressed (images, video, etc.)
    AlreadyCompressed,
    /// Mixed content
    Mixed,
    /// Unknown/binary data
    Unknown,
}

/// Sample size for entropy calculation (256KB)
const ENTROPY_SAMPLE_SIZE: usize = 256 * 1024;

/// Maximum files to sample for entropy
const MAX_FILES_TO_SAMPLE: usize = 50;

/// Analyze a payload for optimal transfer strategy
pub async fn analyze_payload(path: &Path) -> Result<PayloadAnalysis> {
    if !path.exists() {
        return Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Path does not exist: {}", path.display()),
        )));
    }

    let (total_size, file_count, files) = if path.is_dir() {
        let entries = walk_directory(path)?;
        let files: Vec<_> = entries.into_iter().filter(|e| !e.is_dir).collect();
        let total_size = files.iter().map(|f| f.size).sum();
        let file_count = files.len();
        (total_size, file_count, files)
    } else {
        let metadata = std::fs::metadata(path)?;
        let entry = warp_io::walker::FileEntry {
            path: path.to_path_buf(),
            relative_path: path.file_name().unwrap_or_default().into(),
            size: metadata.len(),
            is_dir: false,
        };
        (metadata.len(), 1, vec![entry])
    };

    let mut file_types = HashMap::new();
    let mut entropy_samples = Vec::new();
    let mut already_compressed_count = 0;

    let sample_count = files.len().min(MAX_FILES_TO_SAMPLE);
    let step = if files.len() > sample_count {
        files.len() / sample_count
    } else {
        1
    };

    for (idx, entry) in files.iter().enumerate() {
        if idx % step != 0 && entropy_samples.len() >= sample_count {
            continue;
        }

        if let Some(ext) = entry.path.extension()
            && let Some(ext_str) = ext.to_str()
        {
            *file_types.entry(ext_str.to_lowercase()).or_insert(0) += 1;
        }

        if entry.size > 0
            && entropy_samples.len() < MAX_FILES_TO_SAMPLE
            && let Ok(entropy) = sample_entropy(&entry.path, ENTROPY_SAMPLE_SIZE)
        {
            entropy_samples.push(entropy);

            if entropy > 0.9 {
                already_compressed_count += 1;
            }
        }
    }

    let avg_entropy = if entropy_samples.is_empty() {
        0.5
    } else {
        entropy_samples.iter().sum::<f64>() / entropy_samples.len() as f64
    };

    let compression_hint = determine_compression_hint(
        avg_entropy,
        &file_types,
        already_compressed_count,
        entropy_samples.len(),
    );

    let chunk_size_hint = calculate_chunk_size(total_size, file_count);

    Ok(PayloadAnalysis {
        total_size,
        file_count,
        avg_entropy,
        compression_hint,
        chunk_size_hint,
        file_types,
    })
}

/// Sample file entropy using warp_compress::adaptive::calculate_entropy
fn sample_entropy(path: &Path, sample_size: usize) -> std::io::Result<f64> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; sample_size];

    let bytes_read = file.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(0.5);
    }

    buffer.truncate(bytes_read);
    Ok(calculate_entropy(&buffer))
}

/// Determine compression hint from analysis
fn determine_compression_hint(
    avg_entropy: f64,
    file_types: &HashMap<String, usize>,
    already_compressed_count: usize,
    total_sampled: usize,
) -> CompressionHint {
    let already_compressed_ratio = if total_sampled > 0 {
        already_compressed_count as f64 / total_sampled as f64
    } else {
        0.0
    };

    if already_compressed_ratio > 0.7 {
        return CompressionHint::AlreadyCompressed;
    }

    let compressed_extensions = [
        "jpg", "jpeg", "png", "gif", "webp", "mp4", "mkv", "avi", "mov", "mp3", "flac", "ogg",
        "zip", "gz", "bz2", "xz", "7z", "rar", "tar", "warp",
    ];

    let compressible_extensions = [
        "txt", "log", "json", "xml", "yaml", "yml", "toml", "md", "rst", "csv", "html", "css",
        "js", "ts", "rs", "c", "cpp", "h", "py", "rb", "go", "java", "sql",
    ];

    let mut compressed_count = 0;
    let mut compressible_count = 0;
    let total_files: usize = file_types.values().sum();

    for (ext, count) in file_types {
        if compressed_extensions.contains(&ext.as_str()) {
            compressed_count += count;
        } else if compressible_extensions.contains(&ext.as_str()) {
            compressible_count += count;
        }
    }

    if total_files > 0 {
        let compressed_ratio = compressed_count as f64 / total_files as f64;
        let compressible_ratio = compressible_count as f64 / total_files as f64;

        if compressed_ratio > 0.6 {
            return CompressionHint::AlreadyCompressed;
        }

        if compressible_ratio > 0.6 {
            return CompressionHint::HighlyCompressible;
        }

        if compressed_ratio > 0.2 && compressible_ratio > 0.2 {
            return CompressionHint::Mixed;
        }
    }

    if avg_entropy > 0.85 {
        CompressionHint::AlreadyCompressed
    } else if avg_entropy < 0.4 {
        CompressionHint::HighlyCompressible
    } else if avg_entropy > 0.5 && avg_entropy < 0.85 {
        CompressionHint::Mixed
    } else {
        CompressionHint::Unknown
    }
}

/// Calculate optimal chunk size based on file sizes
fn calculate_chunk_size(total_size: u64, file_count: usize) -> u32 {
    if file_count == 0 {
        return 4 * 1024 * 1024;
    }

    let avg_file_size = total_size / file_count as u64;

    if avg_file_size < 256 * 1024 {
        1024 * 1024
    } else if avg_file_size < 1024 * 1024 {
        2 * 1024 * 1024
    } else if avg_file_size < 10 * 1024 * 1024 {
        4 * 1024 * 1024
    } else if avg_file_size < 100 * 1024 * 1024 {
        8 * 1024 * 1024
    } else {
        16 * 1024 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_analyze_single_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"hello world").unwrap();
        drop(file);

        let analysis = analyze_payload(&file_path).await.unwrap();
        assert_eq!(analysis.file_count, 1);
        assert_eq!(analysis.total_size, 11);
    }

    #[tokio::test]
    async fn test_analyze_directory() {
        let dir = tempdir().unwrap();
        File::create(dir.path().join("a.txt"))
            .unwrap()
            .write_all(b"hello")
            .unwrap();
        File::create(dir.path().join("b.txt"))
            .unwrap()
            .write_all(b"world")
            .unwrap();

        let analysis = analyze_payload(dir.path()).await.unwrap();
        assert_eq!(analysis.file_count, 2);
        assert_eq!(analysis.total_size, 10);
    }

    #[test]
    fn test_calculate_chunk_size() {
        assert_eq!(calculate_chunk_size(100 * 1024, 1), 1 * 1024 * 1024);
        assert_eq!(calculate_chunk_size(500 * 1024, 1), 2 * 1024 * 1024);
        assert_eq!(calculate_chunk_size(5 * 1024 * 1024, 1), 4 * 1024 * 1024);
        assert_eq!(calculate_chunk_size(50 * 1024 * 1024, 1), 8 * 1024 * 1024);
        assert_eq!(calculate_chunk_size(200 * 1024 * 1024, 1), 16 * 1024 * 1024);
    }

    #[test]
    fn test_compression_hint_high_entropy() {
        let file_types = HashMap::new();
        let hint = determine_compression_hint(0.95, &file_types, 0, 0);
        assert_eq!(hint, CompressionHint::AlreadyCompressed);
    }

    #[test]
    fn test_compression_hint_low_entropy() {
        let file_types = HashMap::new();
        let hint = determine_compression_hint(0.3, &file_types, 0, 0);
        assert_eq!(hint, CompressionHint::HighlyCompressible);
    }
}
