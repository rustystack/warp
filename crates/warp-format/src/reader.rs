//! Reader implementation for .warp archives

use crate::{
    Error, Result,
    file_table::{FileEntry, FileTable},
    header::{Compression, Encryption, HEADER_SIZE, Header},
    index::ChunkIndex,
    merkle::{MerkleTree, SparseMerkleTree},
};
use memmap2::Mmap;
use std::{fs::File, path::Path, sync::Arc};
use warp_compress::{Compressor, Lz4Compressor, ZstdCompressor};
use warp_crypto::encrypt::Key;

/// Reader for .warp archives
///
/// Provides efficient memory-mapped access to archive contents with:
/// - Zero-copy chunk reading via memory mapping
/// - Fast file lookup via file table
/// - Incremental verification support
/// - Automatic decompression
/// - Automatic decryption (if key provided)
/// - Optional sparse Merkle tree for O(log n) chunk verification
pub struct WarpReader {
    /// Memory-mapped archive file
    mmap: Mmap,
    /// Parsed header
    header: Header,
    /// Chunk index for locating chunk data
    chunk_index: ChunkIndex,
    /// File table for path-to-chunk mapping
    file_table: FileTable,
    /// Decompressor instance
    decompressor: Arc<dyn Compressor>,
    /// Decryption key (if archive is encrypted)
    decryption_key: Option<Key>,
    /// Sparse Merkle tree for efficient verification (optional)
    sparse_tree: Option<SparseMerkleTree>,
}

impl WarpReader {
    /// Open a .warp archive for reading
    ///
    /// This memory-maps the archive file and parses all metadata structures:
    /// - Header (first 256 bytes)
    /// - Chunk index (at header.index_offset)
    /// - File table (at header.file_table_offset)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File cannot be opened or memory-mapped
    /// - Header is invalid or corrupted
    /// - Index or file table cannot be parsed
    /// - Compression algorithm is unsupported
    /// - Archive is encrypted (use `open_encrypted` instead)
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_internal(path, None)
    }

    /// Open an encrypted .warp archive for reading
    ///
    /// This is similar to `open`, but accepts a decryption key for
    /// encrypted archives.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the archive file
    /// * `key` - Decryption key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File cannot be opened or memory-mapped
    /// - Header is invalid or corrupted
    /// - Index or file table cannot be parsed
    /// - Compression algorithm is unsupported
    pub fn open_encrypted(path: &Path, key: Key) -> Result<Self> {
        Self::open_internal(path, Some(key))
    }

    /// Open a .warp archive with sparse Merkle tree for efficient verification
    ///
    /// This builds a sparse Merkle tree from the chunk hashes stored in the
    /// index, enabling O(log n) single-chunk verification without reading
    /// all chunks.
    ///
    /// # Performance
    ///
    /// - Construction: O(n) where n is the number of chunks
    /// - Memory: O(n) for leaf hashes + O(cache_size) for internal nodes
    /// - Single verification: O(log n)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use warp_format::WarpReader;
    /// use std::path::Path;
    ///
    /// let reader = WarpReader::open_with_verification(Path::new("archive.warp"))?;
    ///
    /// // Fast verification of a single chunk
    /// if reader.verify_chunk_fast(42)? {
    ///     println!("Chunk 42 is valid");
    /// }
    /// # Ok::<(), warp_format::Error>(())
    /// ```
    pub fn open_with_verification(path: &Path) -> Result<Self> {
        let mut reader = Self::open_internal(path, None)?;
        reader.build_verification_tree();
        Ok(reader)
    }

    /// Open an encrypted .warp archive with sparse Merkle tree
    ///
    /// Combines encrypted archive support with efficient verification.
    pub fn open_encrypted_with_verification(path: &Path, key: Key) -> Result<Self> {
        let mut reader = Self::open_internal(path, Some(key))?;
        reader.build_verification_tree();
        Ok(reader)
    }

    /// Build the sparse Merkle tree for efficient verification
    ///
    /// This extracts chunk hashes from the index and builds a sparse
    /// Merkle tree. The tree is built lazily - only the root is computed
    /// immediately, internal nodes are computed on demand.
    ///
    /// Call this method after opening if you need fast chunk verification
    /// but didn't use `open_with_verification`.
    pub fn build_verification_tree(&mut self) {
        // Handle empty archives gracefully - no tree needed
        if self.chunk_index.is_empty() {
            return;
        }

        let hashes: Vec<[u8; 32]> = (0..self.chunk_index.len())
            .map(|i| self.chunk_index.get(i).unwrap().hash)
            .collect();

        debug_assert_eq!(
            hashes.len(),
            self.chunk_index.len(),
            "hash count must match chunk count"
        );

        self.sparse_tree = Some(SparseMerkleTree::from_leaves(hashes));
    }

    /// Check if the verification tree is built
    pub fn has_verification_tree(&self) -> bool {
        self.sparse_tree.is_some()
    }

    /// Verify a single chunk using the sparse Merkle tree (O(log n))
    ///
    /// This method uses the pre-built sparse Merkle tree for fast
    /// verification. It reads and hashes the chunk, then verifies
    /// the hash against the tree.
    ///
    /// # Arguments
    ///
    /// * `index` - Zero-based chunk index
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the chunk is valid
    /// - `Ok(false)` if the chunk hash doesn't match
    /// - `Err` if reading fails or verification tree not built
    ///
    /// # Performance
    ///
    /// This is O(log n) in the number of chunks, compared to O(n)
    /// for full archive verification.
    pub fn verify_chunk_fast(&self, index: usize) -> Result<bool> {
        let tree = self.sparse_tree.as_ref().ok_or_else(|| {
            Error::Corrupted(
                "Verification tree not built. Call build_verification_tree() first".into(),
            )
        })?;

        if index >= self.chunk_index.len() {
            return Err(Error::Corrupted(format!("Invalid chunk index: {}", index)));
        }

        // Read and hash the chunk
        let chunk_data = self.read_chunk(index)?;
        let computed_hash = warp_hash::hash(&chunk_data);

        // Verify against the tree
        Ok(tree.verify_chunk(index, &computed_hash))
    }

    /// Randomly verify a sample of chunks for integrity checking
    ///
    /// This method selects random chunks and verifies each one using
    /// the sparse Merkle tree. Useful for quick spot-checks of large
    /// archives without verifying every chunk.
    ///
    /// # Arguments
    ///
    /// * `sample_size` - Number of chunks to randomly sample and verify
    ///
    /// # Returns
    ///
    /// A tuple of (verified_count, total_sampled) where:
    /// - `verified_count` is the number of chunks that passed verification
    /// - `total_sampled` is the actual number of chunks sampled
    ///
    /// # Example
    ///
    /// ```no_run
    /// use warp_format::WarpReader;
    /// use std::path::Path;
    ///
    /// let reader = WarpReader::open_with_verification(Path::new("archive.warp"))?;
    ///
    /// // Verify 100 random chunks
    /// let (passed, total) = reader.verify_random_sample(100)?;
    /// println!("{}/{} chunks verified successfully", passed, total);
    /// # Ok::<(), warp_format::Error>(())
    /// ```
    pub fn verify_random_sample(&self, sample_size: usize) -> Result<(usize, usize)> {
        use rand::seq::SliceRandom;

        // Handle empty archives gracefully - no verification needed
        if self.chunk_index.is_empty() {
            return Ok((0, 0));
        }

        let tree = self.sparse_tree.as_ref().ok_or_else(|| {
            Error::Corrupted(
                "Verification tree not built. Call build_verification_tree() first".into(),
            )
        })?;

        let actual_sample = sample_size.min(self.chunk_index.len());
        let mut rng = rand::thread_rng();

        // Select random indices
        let indices: Vec<usize> = (0..self.chunk_index.len())
            .collect::<Vec<_>>()
            .choose_multiple(&mut rng, actual_sample)
            .copied()
            .collect();

        let mut verified = 0;

        for index in &indices {
            // Read and hash the chunk
            let chunk_data = self.read_chunk(*index)?;
            let computed_hash = warp_hash::hash(&chunk_data);

            if tree.verify_chunk(*index, &computed_hash) {
                verified += 1;
            }
        }

        Ok((verified, actual_sample))
    }

    /// Get the sparse Merkle tree root hash
    ///
    /// Returns the root hash of the sparse Merkle tree, or None
    /// if the tree hasn't been built.
    pub fn sparse_tree_root(&self) -> Option<[u8; 32]> {
        self.sparse_tree.as_ref().map(|t| t.root())
    }

    /// Internal implementation for opening archives
    fn open_internal(path: &Path, decryption_key: Option<Key>) -> Result<Self> {
        // Open and memory-map the file
        let file = File::open(path)?;
        // SAFETY: The File handle is valid (just opened successfully). The mmap remains
        // valid for the lifetime of WarpReader because we store both file and mmap.
        // Read-only mapping is safe even if file is modified externally (we may see
        // stale data but no UB).
        let mmap = unsafe { Mmap::map(&file)? };

        // Validate minimum size for header
        if mmap.len() < HEADER_SIZE {
            return Err(Error::Corrupted(format!(
                "File too small: {} bytes (expected at least {})",
                mmap.len(),
                HEADER_SIZE
            )));
        }

        // Parse and validate header
        let header_bytes: [u8; HEADER_SIZE] = mmap[0..HEADER_SIZE]
            .try_into()
            .map_err(|_| Error::Corrupted("Failed to read header".into()))?;
        let header = Header::from_bytes(&header_bytes)?;

        // Check if archive is encrypted and key was provided
        if header.encryption != Encryption::None && decryption_key.is_none() {
            return Err(Error::Corrupted(
                "Archive is encrypted but no decryption key provided. Use open_encrypted()".into(),
            ));
        }

        // Parse chunk index
        let index_start = header.index_offset as usize;
        let index_end = index_start + header.index_size as usize;

        if index_end > mmap.len() {
            return Err(Error::Corrupted(format!(
                "Index extends beyond file: {} > {}",
                index_end,
                mmap.len()
            )));
        }

        let chunk_index = ChunkIndex::from_bytes(&mmap[index_start..index_end])?;

        // Validate chunk count
        if chunk_index.len() != header.total_chunks as usize {
            return Err(Error::Corrupted(format!(
                "Chunk count mismatch: index has {}, header says {}",
                chunk_index.len(),
                header.total_chunks
            )));
        }

        // Parse file table
        let table_start = header.file_table_offset as usize;
        let table_end = table_start + header.file_table_size as usize;

        if table_end > mmap.len() {
            return Err(Error::Corrupted(format!(
                "File table extends beyond file: {} > {}",
                table_end,
                mmap.len()
            )));
        }

        let file_table = FileTable::from_bytes(&mmap[table_start..table_end])?;

        // Validate file count
        if file_table.len() != header.total_files as usize {
            return Err(Error::Corrupted(format!(
                "File count mismatch: table has {}, header says {}",
                file_table.len(),
                header.total_files
            )));
        }

        // Create decompressor based on header
        let decompressor: Arc<dyn Compressor> = match header.compression {
            Compression::None => {
                // For uncompressed archives, we still need a decompressor instance
                // but it won't be used for chunks marked as uncompressed
                Arc::new(ZstdCompressor::new(3)?)
            }
            Compression::Zstd => Arc::new(ZstdCompressor::new(3)?),
            Compression::Lz4 => Arc::new(Lz4Compressor::new()),
        };

        Ok(Self {
            mmap,
            header,
            chunk_index,
            file_table,
            decompressor,
            decryption_key,
            sparse_tree: None,
        })
    }

    /// Check if the archive is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.header.encryption != Encryption::None
    }

    /// Get a reference to the archive header
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// List all files in the archive
    ///
    /// Returns an iterator over file entries, useful for displaying
    /// archive contents or filtering files before extraction.
    pub fn list_files(&self) -> impl Iterator<Item = &FileEntry> {
        self.file_table.iter()
    }

    /// Get the total number of files in the archive
    pub fn file_count(&self) -> usize {
        self.file_table.len()
    }

    /// Get the total number of chunks in the archive
    pub fn chunk_count(&self) -> usize {
        self.chunk_index.len()
    }

    /// Read and decompress a chunk by index
    ///
    /// # Arguments
    ///
    /// * `index` - Zero-based chunk index
    ///
    /// # Returns
    ///
    /// The decompressed chunk data as a vector.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Chunk index is out of bounds
    /// - Chunk data extends beyond file
    /// - Decompression fails
    /// - Hash verification fails (if enabled)
    pub fn read_chunk(&self, index: usize) -> Result<Vec<u8>> {
        // Get chunk entry
        let entry = self
            .chunk_index
            .get(index)
            .ok_or_else(|| Error::Corrupted(format!("Invalid chunk index: {}", index)))?;

        // Calculate chunk boundaries in data section
        let chunk_start = entry.offset as usize;
        let chunk_end = chunk_start + entry.compressed_size as usize;

        if chunk_end > self.mmap.len() {
            return Err(Error::Corrupted(format!(
                "Chunk {} extends beyond file: {} > {}",
                index,
                chunk_end,
                self.mmap.len()
            )));
        }

        // Read data from memory map (may be encrypted)
        let mut chunk_data = self.mmap[chunk_start..chunk_end].to_vec();

        // Decrypt if needed (BEFORE decompression)
        if let Some(ref key) = self.decryption_key {
            chunk_data = warp_crypto::decrypt(key, &chunk_data).map_err(|e| {
                Error::Corrupted(format!("Decryption failed for chunk {}: {}", index, e))
            })?;
        }

        // Decompress if needed (AFTER decryption)
        let data = if entry.is_compressed() {
            self.decompressor.decompress(&chunk_data)?
        } else {
            chunk_data
        };

        // Validate decompressed size
        if data.len() != entry.original_size as usize {
            return Err(Error::Corrupted(format!(
                "Decompressed size mismatch for chunk {}: got {}, expected {}",
                index,
                data.len(),
                entry.original_size
            )));
        }

        // Optionally verify hash
        if cfg!(debug_assertions) {
            let computed_hash = warp_hash::hash(&data);
            if computed_hash != entry.hash {
                return Err(Error::Corrupted(format!(
                    "Hash mismatch for chunk {}",
                    index
                )));
            }
        }

        Ok(data)
    }

    /// Extract a single file from the archive
    ///
    /// # Arguments
    ///
    /// * `archive_path` - Path of the file within the archive
    /// * `dest` - Destination path to write the extracted file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File not found in archive
    /// - Cannot create parent directories
    /// - Chunk reading or decompression fails
    /// - Cannot write output file
    /// - Cannot set file permissions or timestamps (non-fatal on Windows)
    pub fn extract_file(&self, archive_path: &str, dest: &Path) -> Result<()> {
        // Find file in file table
        let file_entry = self.file_table.get_by_path(archive_path).ok_or_else(|| {
            Error::Corrupted(format!("File not found in archive: {}", archive_path))
        })?;

        // Create parent directories
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Read all chunks for this file
        let mut file_data = Vec::with_capacity(file_entry.size as usize);

        for chunk_idx in file_entry.chunk_start..file_entry.chunk_end {
            let chunk_data = self.read_chunk(chunk_idx as usize)?;
            file_data.extend_from_slice(&chunk_data);
        }

        // Verify file size matches
        if file_data.len() != file_entry.size as usize {
            return Err(Error::Corrupted(format!(
                "File size mismatch for {}: got {}, expected {}",
                archive_path,
                file_data.len(),
                file_entry.size
            )));
        }

        // Verify whole-file hash
        let computed_hash = warp_hash::hash(&file_data);
        if computed_hash != file_entry.hash {
            return Err(Error::Corrupted(format!(
                "File hash mismatch for {}",
                archive_path
            )));
        }

        // Write file
        std::fs::write(dest, &file_data)?;

        // Set file permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(file_entry.mode);
            std::fs::set_permissions(dest, perms)?;
        }

        // Set modification time
        use std::time::UNIX_EPOCH;
        let mtime = UNIX_EPOCH + std::time::Duration::from_secs(file_entry.mtime as u64);
        if let Err(e) = filetime::set_file_mtime(dest, filetime::FileTime::from_system_time(mtime))
        {
            // Non-fatal: log but continue
            eprintln!("Warning: failed to set mtime for {}: {}", dest.display(), e);
        }

        Ok(())
    }

    /// Extract all files from the archive
    ///
    /// # Arguments
    ///
    /// * `dest` - Destination directory for extracted files
    ///
    /// # Errors
    ///
    /// Returns an error if any file extraction fails.
    /// Extraction stops at the first error.
    pub fn extract_all(&self, dest: &Path) -> Result<()> {
        for file_entry in self.file_table.iter() {
            let file_dest = dest.join(&file_entry.path);
            self.extract_file(&file_entry.path, &file_dest)?;
        }
        Ok(())
    }

    /// Verify the integrity of all chunks in the archive
    ///
    /// This re-hashes all chunks and rebuilds the Merkle tree
    /// to verify the root hash matches the header.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if verification succeeds, `Ok(false)` if
    /// the Merkle root doesn't match, or an error if chunk reading fails.
    pub fn verify(&self) -> Result<bool> {
        let mut chunk_hashes = Vec::with_capacity(self.chunk_index.len());

        // Re-hash all chunks
        for i in 0..self.chunk_index.len() {
            let chunk_data = self.read_chunk(i)?;
            let hash = warp_hash::hash(&chunk_data);
            chunk_hashes.push(hash);
        }

        // Build Merkle tree
        let tree = MerkleTree::from_leaves(chunk_hashes);
        let computed_root = tree.root();

        // Compare with header
        Ok(computed_root == self.header.merkle_root)
    }

    /// Verify the integrity of a single file
    ///
    /// This re-hashes all chunks belonging to the file and
    /// compares the whole-file hash.
    ///
    /// # Arguments
    ///
    /// * `archive_path` - Path of the file within the archive
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if verification succeeds, `Ok(false)` if
    /// the hash doesn't match, or an error if the file is not found
    /// or chunk reading fails.
    pub fn verify_file(&self, archive_path: &str) -> Result<bool> {
        // Find file in file table
        let file_entry = self.file_table.get_by_path(archive_path).ok_or_else(|| {
            Error::Corrupted(format!("File not found in archive: {}", archive_path))
        })?;

        // Read all chunks for this file
        let mut file_data = Vec::with_capacity(file_entry.size as usize);

        for chunk_idx in file_entry.chunk_start..file_entry.chunk_end {
            let chunk_data = self.read_chunk(chunk_idx as usize)?;
            file_data.extend_from_slice(&chunk_data);
        }

        // Verify size
        if file_data.len() != file_entry.size as usize {
            return Ok(false);
        }

        // Verify hash
        let computed_hash = warp_hash::hash(&file_data);
        Ok(computed_hash == file_entry.hash)
    }

    /// Get a file entry by path
    ///
    /// Returns `None` if the file is not found in the archive.
    pub fn get_file_entry(&self, archive_path: &str) -> Option<&FileEntry> {
        self.file_table.get_by_path(archive_path)
    }

    /// Check if a file exists in the archive
    pub fn contains_file(&self, archive_path: &str) -> bool {
        self.file_table.get_by_path(archive_path).is_some()
    }

    /// Get archive statistics
    ///
    /// Returns a tuple of (original_size, compressed_size, compression_ratio)
    pub fn stats(&self) -> (u64, u64, f64) {
        let ratio = if self.header.original_size > 0 {
            self.header.compressed_size as f64 / self.header.original_size as f64
        } else {
            1.0
        };
        (
            self.header.original_size,
            self.header.compressed_size,
            ratio,
        )
    }
}

// SAFETY: WarpReader is Send + Sync because:
//
// 1. Mmap (memmap2::Mmap):
//    - Thread-safe for concurrent reads (immutable mapping)
//    - The underlying memory is read-only after creation
//    - No internal mutation occurs during read operations
//
// 2. Header, ChunkIndex, FileTable:
//    - All are immutable after construction in open_internal()
//    - No interior mutability (no Cell, RefCell, or UnsafeCell)
//
// 3. Arc<dyn Compressor>:
//    - Already requires Send + Sync bound on the trait object
//    - Compressors (ZstdCompressor, Lz4Compressor) are stateless or thread-safe
//
// 4. Option<Key> (decryption_key):
//    - Key is a simple byte array wrapper, trivially Send + Sync
//
// 5. Option<SparseMerkleTree>:
//    - Built lazily but only via &mut self (build_verification_tree)
//    - Once built, immutable during concurrent reads
//
// Thread-safety guarantee: After construction, WarpReader only performs
// read operations on its fields. No method takes &mut self except
// build_verification_tree(), which should be called before sharing.
// SAFETY: All fields are either Send (File, Option<Key>) or read-only (Mmap, header structs).
// The Mmap is read-only and the underlying File is never modified after construction.
unsafe impl Send for WarpReader {}
// SAFETY: All read operations on WarpReader use &self and don't mutate any fields.
// The Mmap provides read-only access to file contents, which is inherently Sync.
unsafe impl Sync for WarpReader {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::{WarpWriter, WarpWriterConfig};
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_archive(temp_dir: &Path) -> Result<std::path::PathBuf> {
        let archive_path = temp_dir.join("test.warp");
        let source_dir = temp_dir.join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create test files
        let file1_path = source_dir.join("file1.txt");
        let mut file1 = std::fs::File::create(&file1_path)?;
        file1.write_all(b"Hello, world! This is file 1.")?;
        drop(file1);

        let subdir = source_dir.join("subdir");
        std::fs::create_dir_all(&subdir)?;
        let file2_path = subdir.join("file2.txt");
        let mut file2 = std::fs::File::create(&file2_path)?;
        file2.write_all(b"This is file 2 in a subdirectory.")?;
        drop(file2);

        // Create archive
        let config = WarpWriterConfig {
            compression: Compression::Zstd,
            chunk_size: 1024,
            ..Default::default()
        };

        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        Ok(archive_path)
    }

    #[test]
    fn test_reader_open() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        assert_eq!(reader.header().magic, crate::MAGIC);
        assert_eq!(reader.header().version, crate::VERSION);
        assert!(reader.file_count() > 0);
        assert!(reader.chunk_count() > 0);

        Ok(())
    }

    #[test]
    fn test_reader_list_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;
        let files: Vec<_> = reader.list_files().collect();

        assert_eq!(files.len(), 2);

        let paths: Vec<_> = files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&"file1.txt"));
        assert!(paths.contains(&"subdir/file2.txt"));

        Ok(())
    }

    #[test]
    fn test_reader_extract_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        let extract_dir = temp_dir.path().join("extract");
        std::fs::create_dir_all(&extract_dir)?;

        let dest = extract_dir.join("extracted.txt");
        reader.extract_file("file1.txt", &dest)?;

        let content = std::fs::read_to_string(&dest)?;
        assert_eq!(content, "Hello, world! This is file 1.");

        Ok(())
    }

    #[test]
    fn test_reader_extract_all() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        let extract_dir = temp_dir.path().join("extract_all");
        reader.extract_all(&extract_dir)?;

        let file1 = std::fs::read_to_string(extract_dir.join("file1.txt"))?;
        assert_eq!(file1, "Hello, world! This is file 1.");

        let file2 = std::fs::read_to_string(extract_dir.join("subdir/file2.txt"))?;
        assert_eq!(file2, "This is file 2 in a subdirectory.");

        Ok(())
    }

    #[test]
    fn test_reader_verify() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        let valid = reader.verify()?;
        assert!(valid, "Archive verification should succeed");

        Ok(())
    }

    #[test]
    fn test_reader_verify_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        let valid1 = reader.verify_file("file1.txt")?;
        assert!(valid1, "file1.txt verification should succeed");

        let valid2 = reader.verify_file("subdir/file2.txt")?;
        assert!(valid2, "subdir/file2.txt verification should succeed");

        Ok(())
    }

    #[test]
    fn test_reader_file_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = create_test_archive(temp_dir.path()).unwrap();

        let reader = WarpReader::open(&archive_path).unwrap();

        let result = reader.extract_file("nonexistent.txt", &temp_dir.path().join("out.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_reader_contains_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        assert!(reader.contains_file("file1.txt"));
        assert!(reader.contains_file("subdir/file2.txt"));
        assert!(!reader.contains_file("nonexistent.txt"));

        Ok(())
    }

    #[test]
    fn test_reader_get_file_entry() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        let entry = reader.get_file_entry("file1.txt");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().path, "file1.txt");

        let missing = reader.get_file_entry("nonexistent.txt");
        assert!(missing.is_none());

        Ok(())
    }

    #[test]
    fn test_reader_stats() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        let (original, compressed, ratio) = reader.stats();
        assert!(original > 0);
        assert!(compressed > 0);
        assert!(ratio > 0.0);
        assert!(ratio <= 1.0);

        Ok(())
    }

    #[test]
    fn test_reader_roundtrip_large_file() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("large.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create a larger file with non-compressible data
        let large_file = source_dir.join("large.bin");
        let mut data = Vec::with_capacity(10 * 1024);
        for i in 0..10 * 1024 {
            data.push((i % 256) as u8); // Non-repeating pattern
        }
        std::fs::write(&large_file, &data)?;

        // Create archive
        let config = WarpWriterConfig {
            compression: Compression::Zstd,
            chunk_size: 2048, // 2KB chunks
            ..Default::default()
        };

        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        // Read back and verify
        let reader = WarpReader::open(&archive_path)?;
        assert!(reader.chunk_count() > 0, "Should have at least one chunk");
        assert!(reader.file_count() == 1, "Should have exactly one file");

        let extract_dir = temp_dir.path().join("extract");
        reader.extract_all(&extract_dir)?;

        let extracted_data = std::fs::read(extract_dir.join("large.bin"))?;
        assert_eq!(extracted_data, data, "Roundtrip data should match");

        Ok(())
    }

    #[test]
    fn test_reader_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let invalid_file = temp_dir.path().join("invalid.warp");
        std::fs::write(&invalid_file, b"not a warp file").unwrap();

        let result = WarpReader::open(&invalid_file);
        assert!(result.is_err());
    }

    #[test]
    fn test_reader_empty_archive() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("empty.warp");
        let source_dir = temp_dir.path().join("empty_source");
        std::fs::create_dir_all(&source_dir)?;

        // Create empty archive
        let config = WarpWriterConfig::default();
        let writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.finish()?;

        // Read back
        let reader = WarpReader::open(&archive_path)?;
        assert_eq!(reader.file_count(), 0);
        assert_eq!(reader.chunk_count(), 0);

        let extract_dir = temp_dir.path().join("extract");
        reader.extract_all(&extract_dir)?;

        Ok(())
    }

    #[test]
    fn test_read_chunk() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        // Read first chunk
        let chunk_data = reader.read_chunk(0)?;
        assert!(!chunk_data.is_empty());

        Ok(())
    }

    #[test]
    fn test_read_chunk_invalid_index() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        let result = reader.read_chunk(9999);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_encrypted_roundtrip() -> Result<()> {
        use warp_crypto::encrypt::Key;

        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("encrypted.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create test file
        let test_file = source_dir.join("secret.txt");
        let original_content = b"This is secret data that should be encrypted!";
        std::fs::write(&test_file, original_content)?;

        // Create encrypted archive
        let key = Key::generate();
        let config = WarpWriterConfig::default().with_encryption(key.clone());
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_file(&test_file, "secret.txt")?;
        writer.finish()?;

        // Open encrypted archive with key
        let reader = WarpReader::open_encrypted(&archive_path, key)?;
        assert!(reader.is_encrypted());

        // Extract and verify
        let extract_dir = temp_dir.path().join("extracted");
        reader.extract_all(&extract_dir)?;

        let extracted_content = std::fs::read(extract_dir.join("secret.txt"))?;
        assert_eq!(extracted_content, original_content);

        Ok(())
    }

    #[test]
    fn test_encrypted_without_key_fails() -> Result<()> {
        use warp_crypto::encrypt::Key;

        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("encrypted.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create test file
        let test_file = source_dir.join("data.txt");
        std::fs::write(&test_file, b"Test data")?;

        // Create encrypted archive
        let key = Key::generate();
        let config = WarpWriterConfig::default().with_encryption(key);
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_file(&test_file, "data.txt")?;
        writer.finish()?;

        // Try to open without key - should fail
        let result = WarpReader::open(&archive_path);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_encrypted_wrong_key_fails() -> Result<()> {
        use warp_crypto::encrypt::Key;

        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("encrypted.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create test file
        let test_file = source_dir.join("data.txt");
        std::fs::write(&test_file, b"Test data")?;

        // Create encrypted archive with one key
        let key1 = Key::generate();
        let config = WarpWriterConfig::default().with_encryption(key1);
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_file(&test_file, "data.txt")?;
        writer.finish()?;

        // Try to open with different key
        let key2 = Key::generate();
        let reader = WarpReader::open_encrypted(&archive_path, key2)?;

        // Reading should fail due to wrong key
        let result = reader.read_chunk(0);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_encrypted_multiple_files_roundtrip() -> Result<()> {
        use warp_crypto::encrypt::Key;

        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("encrypted.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create multiple test files
        std::fs::write(source_dir.join("file1.txt"), b"Content 1")?;
        std::fs::write(source_dir.join("file2.txt"), b"Content 2")?;
        std::fs::write(source_dir.join("file3.txt"), b"Content 3")?;

        // Create encrypted archive
        let key = Key::generate();
        let config = WarpWriterConfig::default().with_encryption(key.clone());
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        // Open and extract
        let reader = WarpReader::open_encrypted(&archive_path, key)?;
        let extract_dir = temp_dir.path().join("extracted");
        reader.extract_all(&extract_dir)?;

        // Verify all files
        assert_eq!(std::fs::read(extract_dir.join("file1.txt"))?, b"Content 1");
        assert_eq!(std::fs::read(extract_dir.join("file2.txt"))?, b"Content 2");
        assert_eq!(std::fs::read(extract_dir.join("file3.txt"))?, b"Content 3");

        Ok(())
    }

    #[test]
    fn test_encrypted_large_file_roundtrip() -> Result<()> {
        use warp_crypto::encrypt::Key;

        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("encrypted.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create a larger file
        let large_file = source_dir.join("large.bin");
        let mut data = Vec::with_capacity(100 * 1024);
        for i in 0..100 * 1024 {
            data.push((i % 256) as u8);
        }
        std::fs::write(&large_file, &data)?;

        // Create encrypted archive
        let key = Key::generate();
        let config = WarpWriterConfig {
            compression: Compression::Zstd,
            chunk_size: 4096, // Small chunks to test multiple encryptions
            encryption: Encryption::ChaCha20Poly1305,
            encryption_key: Some(key.clone()),
            ..Default::default()
        };
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_file(&large_file, "large.bin")?;
        writer.finish()?;

        // Open and extract
        let reader = WarpReader::open_encrypted(&archive_path, key)?;
        let extract_dir = temp_dir.path().join("extracted");
        reader.extract_all(&extract_dir)?;

        // Verify file matches
        let extracted = std::fs::read(extract_dir.join("large.bin"))?;
        assert_eq!(extracted, data);

        Ok(())
    }

    #[test]
    fn test_encrypted_verify() -> Result<()> {
        use warp_crypto::encrypt::Key;

        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("encrypted.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create test file
        std::fs::write(source_dir.join("data.txt"), b"Test data for verification")?;

        // Create encrypted archive
        let key = Key::generate();
        let config = WarpWriterConfig::default().with_encryption(key.clone());
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        // Open and verify
        let reader = WarpReader::open_encrypted(&archive_path, key)?;
        let valid = reader.verify()?;
        assert!(valid, "Encrypted archive verification should succeed");

        Ok(())
    }

    #[test]
    fn test_is_encrypted() -> Result<()> {
        use warp_crypto::encrypt::Key;

        let temp_dir = TempDir::new()?;

        // Create unencrypted archive
        let unencrypted_path = temp_dir.path().join("unencrypted.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;
        std::fs::write(source_dir.join("file.txt"), b"Test")?;

        let mut writer = WarpWriter::create(&unencrypted_path)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        let reader = WarpReader::open(&unencrypted_path)?;
        assert!(!reader.is_encrypted());

        // Create encrypted archive
        let encrypted_path = temp_dir.path().join("encrypted.warp");
        let key = Key::generate();
        let config = WarpWriterConfig::default().with_encryption(key.clone());
        let mut writer = WarpWriter::create_with_config(&encrypted_path, config)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        let reader = WarpReader::open_encrypted(&encrypted_path, key)?;
        assert!(reader.is_encrypted());

        Ok(())
    }

    // =========================================================================
    // Sparse Merkle Tree Verification Tests
    // =========================================================================

    #[test]
    fn test_open_with_verification() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open_with_verification(&archive_path)?;

        assert!(reader.has_verification_tree());
        assert!(reader.sparse_tree_root().is_some());

        // The sparse tree root should match the header merkle root
        assert_eq!(
            reader.sparse_tree_root().unwrap(),
            reader.header().merkle_root
        );

        Ok(())
    }

    #[test]
    fn test_build_verification_tree_manually() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let mut reader = WarpReader::open(&archive_path)?;

        // Initially no tree
        assert!(!reader.has_verification_tree());

        // Build the tree
        reader.build_verification_tree();

        // Now we have a tree
        assert!(reader.has_verification_tree());
        assert_eq!(
            reader.sparse_tree_root().unwrap(),
            reader.header().merkle_root
        );

        Ok(())
    }

    #[test]
    fn test_verify_chunk_fast() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open_with_verification(&archive_path)?;

        // Verify all chunks
        for i in 0..reader.chunk_count() {
            let valid = reader.verify_chunk_fast(i)?;
            assert!(valid, "Chunk {} should verify", i);
        }

        Ok(())
    }

    #[test]
    fn test_verify_chunk_fast_without_tree_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        // Should fail because tree not built
        let result = reader.verify_chunk_fast(0);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_verify_chunk_fast_invalid_index() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open_with_verification(&archive_path)?;

        // Should fail for invalid index
        let result = reader.verify_chunk_fast(9999);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_verify_random_sample() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("multi_chunk.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create multiple files to ensure multiple chunks
        for i in 0..10 {
            let file_path = source_dir.join(format!("file{}.txt", i));
            std::fs::write(&file_path, format!("Content for file number {}", i))?;
        }

        // Create archive with small chunks and no compression
        // to ensure we get multiple chunks
        let config = WarpWriterConfig {
            compression: Compression::None,
            chunk_size: 32, // Very small chunks
            ..Default::default()
        };
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        // Open with verification
        let reader = WarpReader::open_with_verification(&archive_path)?;

        // Verify random sample (may have single or multiple chunks)
        let (verified, total) = reader.verify_random_sample(5)?;
        assert_eq!(verified, total, "All sampled chunks should verify");
        // Total should be at most 5 or the total chunk count
        assert!(total <= 5 || total == reader.chunk_count());

        Ok(())
    }

    #[test]
    fn test_verify_random_sample_without_tree_fails() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = create_test_archive(temp_dir.path())?;

        let reader = WarpReader::open(&archive_path)?;

        // Should fail because tree not built
        let result = reader.verify_random_sample(5);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_verify_random_sample_empty_archive() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("empty.warp");

        // Create empty archive
        let writer = WarpWriter::create(&archive_path)?;
        writer.finish()?;

        let reader = WarpReader::open_with_verification(&archive_path)?;

        // Should return (0, 0) for empty archive
        let (verified, total) = reader.verify_random_sample(10)?;
        assert_eq!(verified, 0);
        assert_eq!(total, 0);

        Ok(())
    }

    #[test]
    fn test_encrypted_with_verification() -> Result<()> {
        use warp_crypto::encrypt::Key;

        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("encrypted.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create test files
        std::fs::write(source_dir.join("file1.txt"), b"Content 1")?;
        std::fs::write(source_dir.join("file2.txt"), b"Content 2")?;

        // Create encrypted archive
        let key = Key::generate();
        let config = WarpWriterConfig::default().with_encryption(key.clone());
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        // Open with verification
        let reader = WarpReader::open_encrypted_with_verification(&archive_path, key)?;

        assert!(reader.is_encrypted());
        assert!(reader.has_verification_tree());

        // Verify all chunks
        for i in 0..reader.chunk_count() {
            let valid = reader.verify_chunk_fast(i)?;
            assert!(valid, "Encrypted chunk {} should verify", i);
        }

        Ok(())
    }

    #[test]
    fn test_sparse_tree_root_matches_header() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path().join("test.warp");
        let source_dir = temp_dir.path().join("source");
        std::fs::create_dir_all(&source_dir)?;

        // Create files
        for i in 0..10 {
            std::fs::write(
                source_dir.join(format!("file{}.txt", i)),
                format!("Content for file {}", i).as_bytes(),
            )?;
        }

        let config = WarpWriterConfig {
            compression: Compression::Zstd,
            chunk_size: 1024,
            ..Default::default()
        };
        let mut writer = WarpWriter::create_with_config(&archive_path, config)?;
        writer.add_directory(&source_dir, "")?;
        writer.finish()?;

        // Open with verification
        let reader = WarpReader::open_with_verification(&archive_path)?;

        // The sparse tree should produce the same root as stored in header
        let sparse_root = reader.sparse_tree_root().unwrap();
        let header_root = reader.header().merkle_root;

        assert_eq!(
            sparse_root, header_root,
            "Sparse tree root should match header merkle root"
        );

        Ok(())
    }
}
