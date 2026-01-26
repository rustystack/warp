//! Transfer pipeline with parallel chunk processing

use crate::Result;
use crate::scheduler::ChunkScheduler;
use std::sync::Arc;
use tokio::sync::Semaphore;
use warp_compress::Compressor;

/// Pipeline stage for chunk processing
pub struct TransferPipeline {
    scheduler: ChunkScheduler,
    semaphore: Arc<Semaphore>,
    compressor: Option<Box<dyn Compressor>>,
}

impl TransferPipeline {
    /// Create a new transfer pipeline
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            scheduler: ChunkScheduler::new(),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            compressor: None,
        }
    }

    /// Set compressor for the pipeline
    pub fn with_compression(mut self, compressor: Box<dyn Compressor>) -> Self {
        self.compressor = Some(compressor);
        self
    }

    /// Schedule chunks with priorities
    pub fn schedule_chunks(&mut self, chunks: Vec<(u64, i32)>) {
        debug_assert!(
            !chunks.is_empty(),
            "schedule_chunks called with empty chunk list"
        );
        for (chunk_id, priority) in chunks {
            self.scheduler.schedule(chunk_id, priority);
        }
    }

    /// Get next chunk to process
    pub fn next_chunk(&mut self) -> Option<u64> {
        self.scheduler.next_chunk()
    }

    /// Check if pipeline is empty
    pub fn is_empty(&self) -> bool {
        self.scheduler.is_empty()
    }

    /// Process chunks in parallel with a processor function
    ///
    /// # Errors
    ///
    /// Returns an error if the concurrency semaphore is closed (should not happen
    /// under normal operation, but handles edge cases gracefully).
    pub async fn process_chunks<F, Fut>(
        &self,
        chunk_count: usize,
        mut processor: F,
    ) -> Result<Vec<Result<()>>>
    where
        F: FnMut(u64) -> Fut,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        debug_assert!(chunk_count > 0, "process_chunks called with chunk_count 0");
        let mut handles = Vec::new();

        for chunk_id in 0..chunk_count {
            let permit = self
                .semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| crate::Error::Session("concurrency semaphore closed".into()))?;
            let fut = processor(chunk_id as u64);

            let handle = tokio::spawn(async move {
                let result = fut.await;
                drop(permit);
                result
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(crate::Error::Session(format!(
                    "Task join error: {}",
                    e
                )))),
            }
        }

        debug_assert_eq!(
            results.len(),
            chunk_count,
            "results count {} must match chunk_count {}",
            results.len(),
            chunk_count
        );

        Ok(results)
    }

    /// Process a single chunk with optional compression
    pub fn process_chunk(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        if let Some(ref compressor) = self.compressor {
            compressor
                .compress(&data)
                .map_err(|e| crate::Error::Session(format!("Compression failed: {}", e)))
        } else {
            Ok(data)
        }
    }

    /// Decompress a chunk if compressor is set
    pub fn decompress_chunk(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        if let Some(ref compressor) = self.compressor {
            compressor
                .decompress(&data)
                .map_err(|e| crate::Error::Session(format!("Decompression failed: {}", e)))
        } else {
            Ok(data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp_compress::Lz4Compressor;

    #[tokio::test]
    async fn test_pipeline_creation() {
        let pipeline = TransferPipeline::new(4);
        assert!(pipeline.is_empty());
    }

    #[tokio::test]
    async fn test_pipeline_with_compression() {
        let compressor = Box::new(Lz4Compressor::new());
        let pipeline = TransferPipeline::new(4).with_compression(compressor);

        let data = b"hello world".to_vec();
        let compressed = pipeline.process_chunk(data.clone()).unwrap();
        let decompressed = pipeline.decompress_chunk(compressed).unwrap();

        assert_eq!(data, decompressed);
    }

    #[tokio::test]
    async fn test_schedule_chunks() {
        let mut pipeline = TransferPipeline::new(4);
        pipeline.schedule_chunks(vec![(0, 10), (1, 20), (2, 5)]);

        assert_eq!(pipeline.next_chunk(), Some(1));
        assert_eq!(pipeline.next_chunk(), Some(0));
        assert_eq!(pipeline.next_chunk(), Some(2));
        assert_eq!(pipeline.next_chunk(), None);
    }

    #[tokio::test]
    async fn test_process_chunks_parallel() {
        let pipeline = TransferPipeline::new(2);
        let counter = Arc::new(tokio::sync::Mutex::new(0));

        let results = pipeline
            .process_chunks(5, |_chunk_id| {
                let counter = Arc::clone(&counter);
                async move {
                    let mut count = counter.lock().await;
                    *count += 1;
                    Ok(())
                }
            })
            .await
            .unwrap();

        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.is_ok()));

        let final_count = *counter.lock().await;
        assert_eq!(final_count, 5);
    }

    #[tokio::test]
    async fn test_semaphore_limits_concurrency() {
        let pipeline = TransferPipeline::new(2);
        let active = Arc::new(tokio::sync::Mutex::new(0));
        let max_active = Arc::new(tokio::sync::Mutex::new(0));

        let results = pipeline
            .process_chunks(10, |_chunk_id| {
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                async move {
                    let mut curr = active.lock().await;
                    *curr += 1;
                    let current_active = *curr;
                    drop(curr);

                    let mut max = max_active.lock().await;
                    if current_active > *max {
                        *max = current_active;
                    }
                    drop(max);

                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                    let mut curr = active.lock().await;
                    *curr -= 1;

                    Ok(())
                }
            })
            .await
            .unwrap();

        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|r| r.is_ok()));

        let max = *max_active.lock().await;
        assert!(max <= 2, "Max concurrent should be <= 2, got {}", max);
    }
}
