//! Frame codec for wire format
//!
//! This module uses the `Bytes` type for zero-copy buffer sharing.
//! `Bytes` is reference-counted, enabling efficient data passing without allocation.

use crate::frames::{frame_type, Capabilities, FrameHeader};
use crate::{Error, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Maximum frame payload size (16MB)
const MAX_PAYLOAD_SIZE: u32 = 16 * 1024 * 1024;

/// Wire-format Merkle proof for per-chunk verification
///
/// This is the network serialization format for Merkle proofs.
/// Compatible with `warp_format::MerkleProof` but doesn't require the dependency.
#[derive(Debug, Clone)]
pub struct WireMerkleProof {
    /// Sibling hashes from leaf to root (each 32 bytes)
    pub siblings: Vec<[u8; 32]>,
    /// Index of the leaf being proven
    pub leaf_index: u32,
    /// Direction bits packed as bytes (1 bit per level, LSB first)
    pub directions: Vec<u8>,
}

/// A complete frame with header and payload
#[derive(Debug, Clone)]
pub enum Frame {
    /// Hello frame with protocol version
    Hello {
        /// Protocol version
        version: u32,
    },
    /// Capabilities frame
    Capabilities(Capabilities),
    /// Plan frame with transfer details
    Plan {
        /// Total transfer size
        total_size: u64,
        /// Number of chunks
        num_chunks: u32,
        /// Chunk size
        chunk_size: u32,
        /// File metadata (MessagePack encoded, zero-copy)
        metadata: Bytes,
    },
    /// Accept frame
    Accept,
    /// Have frame with chunk IDs
    Have {
        /// Chunk IDs that sender already has
        chunk_ids: Vec<u32>,
    },
    /// Want frame with chunk IDs
    Want {
        /// Chunk IDs that sender wants
        chunk_ids: Vec<u32>,
    },
    /// Chunk frame with data
    Chunk {
        /// Chunk ID
        chunk_id: u32,
        /// Chunk data (zero-copy)
        data: Bytes,
    },
    /// Batch of chunks
    ChunkBatch {
        /// Multiple chunks with (chunk_id, data) pairs (zero-copy)
        chunks: Vec<(u32, Bytes)>,
    },
    /// Erasure-coded shard frame
    Shard {
        /// Original chunk ID this shard belongs to
        chunk_id: u32,
        /// Shard index within the erasure coding scheme
        shard_idx: u16,
        /// Total number of shards (data + parity)
        total_shards: u16,
        /// Shard data (zero-copy)
        data: Bytes,
    },
    /// Acknowledgment frame
    Ack {
        /// Acknowledged chunk IDs
        chunk_ids: Vec<u32>,
    },
    /// Negative acknowledgment frame
    Nack {
        /// Failed chunk IDs
        chunk_ids: Vec<u32>,
        /// Error reason
        reason: String,
    },
    /// Done frame
    Done,
    /// Verify frame with merkle root
    Verify {
        /// Merkle tree root hash
        merkle_root: [u8; 32],
    },
    /// Per-chunk verification with Merkle proof
    ChunkVerify {
        /// Chunk ID being verified
        chunk_id: u32,
        /// Hash of the chunk data
        chunk_hash: [u8; 32],
        /// Merkle proof for O(log n) verification
        proof: WireMerkleProof,
    },
    /// Error frame
    Error {
        /// Error code
        code: u32,
        /// Error message
        message: String,
    },
    /// Cancel frame
    Cancel,
    /// Pause frame
    Pause,
}

impl Frame {
    /// Calculate exact encoded size for pre-allocation
    ///
    /// Returns the total size in bytes including the 8-byte header.
    /// This allows pre-allocating BytesMut to avoid buffer growth during encoding.
    pub fn encoded_size(&self) -> usize {
        let payload_size = match self {
            Self::Hello { .. } => 4,
            Self::Capabilities(caps) => {
                // MessagePack serialization size - estimate based on typical caps
                // This is an estimate; actual size may vary slightly
                rmp_serde::to_vec(caps).map(|v| v.len()).unwrap_or(64)
            }
            Self::Plan { metadata, .. } => 20 + metadata.len(),
            Self::Accept => 0,
            Self::Have { chunk_ids } | Self::Want { chunk_ids } => 4 + chunk_ids.len() * 4,
            Self::Chunk { data, .. } => 8 + data.len(),
            Self::ChunkBatch { chunks } => {
                4 + chunks.iter().map(|(_, d)| 8 + d.len()).sum::<usize>()
            }
            Self::Shard { data, .. } => 12 + data.len(),
            Self::Ack { chunk_ids } => 4 + chunk_ids.len() * 4,
            Self::Nack { chunk_ids, reason } => 4 + chunk_ids.len() * 4 + 4 + reason.len(),
            Self::Done => 0,
            Self::Verify { .. } => 32,
            Self::ChunkVerify { proof, .. } => {
                4 + 32 + 4 + proof.siblings.len() * 32 + 4 + 4 + proof.directions.len()
            }
            Self::Error { message, .. } => 8 + message.len(),
            Self::Cancel | Self::Pause => 0,
        };
        FrameHeader::SIZE + payload_size
    }

    /// Encode frame to a pre-allocated buffer
    ///
    /// This method pre-allocates the buffer to the exact size needed,
    /// avoiding any BytesMut growth during encoding.
    pub fn encode_preallocated(&self) -> Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(self.encoded_size());
        self.encode(&mut buf)?;
        Ok(buf)
    }

    /// Get frame type identifier
    pub fn frame_type(&self) -> u8 {
        match self {
            Self::Hello { .. } => frame_type::HELLO,
            Self::Capabilities(_) => frame_type::CAPABILITIES,
            Self::Plan { .. } => frame_type::PLAN,
            Self::Accept => frame_type::ACCEPT,
            Self::Have { .. } => frame_type::HAVE,
            Self::Want { .. } => frame_type::WANT,
            Self::Chunk { .. } => frame_type::CHUNK,
            Self::ChunkBatch { .. } => frame_type::CHUNK_BATCH,
            Self::Shard { .. } => frame_type::SHARD,
            Self::Ack { .. } => frame_type::ACK,
            Self::Nack { .. } => frame_type::NACK,
            Self::Done => frame_type::DONE,
            Self::Verify { .. } => frame_type::VERIFY,
            Self::ChunkVerify { .. } => frame_type::CHUNK_VERIFY,
            Self::Error { .. } => frame_type::ERROR,
            Self::Cancel => frame_type::CANCEL,
            Self::Pause => frame_type::PAUSE,
        }
    }

    /// Encode frame to bytes
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let payload_start = buf.len() + FrameHeader::SIZE;

        let header = FrameHeader {
            frame_type: self.frame_type(),
            flags: 0,
            stream_id: 0,
            length: 0,
        };
        header.encode(buf);

        match self {
            Self::Hello { version } => {
                buf.put_u32_le(*version);
            }
            Self::Capabilities(caps) => {
                let encoded = rmp_serde::to_vec(caps)
                    .map_err(|e| Error::Protocol(format!("Failed to encode capabilities: {}", e)))?;
                buf.put_slice(&encoded);
            }
            Self::Plan {
                total_size,
                num_chunks,
                chunk_size,
                metadata,
            } => {
                buf.put_u64_le(*total_size);
                buf.put_u32_le(*num_chunks);
                buf.put_u32_le(*chunk_size);
                buf.put_u32_le(metadata.len() as u32);
                buf.put_slice(metadata);
            }
            Self::Accept => {}
            Self::Have { chunk_ids } => {
                buf.put_u32_le(chunk_ids.len() as u32);
                for id in chunk_ids {
                    buf.put_u32_le(*id);
                }
            }
            Self::Want { chunk_ids } => {
                buf.put_u32_le(chunk_ids.len() as u32);
                for id in chunk_ids {
                    buf.put_u32_le(*id);
                }
            }
            Self::Chunk { chunk_id, data } => {
                buf.put_u32_le(*chunk_id);
                buf.put_u32_le(data.len() as u32);
                buf.put_slice(data);
            }
            Self::ChunkBatch { chunks } => {
                buf.put_u32_le(chunks.len() as u32);
                for (chunk_id, data) in chunks {
                    buf.put_u32_le(*chunk_id);
                    buf.put_u32_le(data.len() as u32);
                    buf.put_slice(data);
                }
            }
            Self::Shard {
                chunk_id,
                shard_idx,
                total_shards,
                data,
            } => {
                buf.put_u32_le(*chunk_id);
                buf.put_u16_le(*shard_idx);
                buf.put_u16_le(*total_shards);
                buf.put_u32_le(data.len() as u32);
                buf.put_slice(data);
            }
            Self::Ack { chunk_ids } => {
                buf.put_u32_le(chunk_ids.len() as u32);
                for id in chunk_ids {
                    buf.put_u32_le(*id);
                }
            }
            Self::Nack { chunk_ids, reason } => {
                buf.put_u32_le(chunk_ids.len() as u32);
                for id in chunk_ids {
                    buf.put_u32_le(*id);
                }
                let reason_bytes = reason.as_bytes();
                buf.put_u32_le(reason_bytes.len() as u32);
                buf.put_slice(reason_bytes);
            }
            Self::Done => {}
            Self::Verify { merkle_root } => {
                buf.put_slice(merkle_root);
            }
            Self::ChunkVerify {
                chunk_id,
                chunk_hash,
                proof,
            } => {
                buf.put_u32_le(*chunk_id);
                buf.put_slice(chunk_hash);
                // Encode proof: num_siblings + siblings + leaf_index + directions
                buf.put_u32_le(proof.siblings.len() as u32);
                for sibling in &proof.siblings {
                    buf.put_slice(sibling);
                }
                buf.put_u32_le(proof.leaf_index);
                buf.put_u32_le(proof.directions.len() as u32);
                buf.put_slice(&proof.directions);
            }
            Self::Error { code, message } => {
                buf.put_u32_le(*code);
                let msg_bytes = message.as_bytes();
                buf.put_u32_le(msg_bytes.len() as u32);
                buf.put_slice(msg_bytes);
            }
            Self::Cancel => {}
            Self::Pause => {}
        }

        let payload_len = buf.len() - payload_start;
        if payload_len > MAX_PAYLOAD_SIZE as usize {
            return Err(Error::Protocol(format!(
                "Payload too large: {} bytes",
                payload_len
            )));
        }

        let length_bytes = (payload_len as u32).to_le_bytes();
        buf[payload_start - 4..payload_start].copy_from_slice(&length_bytes);

        Ok(())
    }

    /// Decode frame from bytes
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Self>> {
        if buf.len() < FrameHeader::SIZE {
            return Ok(None);
        }

        let mut header_buf = &buf[..FrameHeader::SIZE];
        let header = FrameHeader::decode(&mut header_buf)?;

        if header.length > MAX_PAYLOAD_SIZE {
            return Err(Error::Protocol(format!(
                "Payload too large: {} bytes",
                header.length
            )));
        }

        let total_size = FrameHeader::SIZE + header.length as usize;
        if buf.len() < total_size {
            return Ok(None);
        }

        buf.advance(FrameHeader::SIZE);

        let frame = match header.frame_type {
            frame_type::HELLO => {
                if buf.remaining() < 4 {
                    return Err(Error::Protocol("Incomplete HELLO frame".into()));
                }
                let version = buf.get_u32_le();
                Self::Hello { version }
            }
            frame_type::CAPABILITIES => {
                let payload = buf.split_to(header.length as usize);
                let caps = rmp_serde::from_slice(&payload)
                    .map_err(|e| Error::Protocol(format!("Failed to decode capabilities: {}", e)))?;
                Self::Capabilities(caps)
            }
            frame_type::PLAN => {
                if buf.remaining() < 20 {
                    return Err(Error::Protocol("Incomplete PLAN frame".into()));
                }
                let total_size = buf.get_u64_le();
                let num_chunks = buf.get_u32_le();
                let chunk_size = buf.get_u32_le();
                let metadata_len = buf.get_u32_le();

                if buf.remaining() < metadata_len as usize {
                    return Err(Error::Protocol("Incomplete PLAN metadata".into()));
                }
                let metadata = buf.split_to(metadata_len as usize).freeze();

                Self::Plan {
                    total_size,
                    num_chunks,
                    chunk_size,
                    metadata,
                }
            }
            frame_type::ACCEPT => Self::Accept,
            frame_type::HAVE => {
                if buf.remaining() < 4 {
                    return Err(Error::Protocol("Incomplete HAVE frame".into()));
                }
                let count = buf.get_u32_le();
                let mut chunk_ids = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    if buf.remaining() < 4 {
                        return Err(Error::Protocol("Incomplete HAVE chunk IDs".into()));
                    }
                    chunk_ids.push(buf.get_u32_le());
                }
                Self::Have { chunk_ids }
            }
            frame_type::WANT => {
                if buf.remaining() < 4 {
                    return Err(Error::Protocol("Incomplete WANT frame".into()));
                }
                let count = buf.get_u32_le();
                let mut chunk_ids = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    if buf.remaining() < 4 {
                        return Err(Error::Protocol("Incomplete WANT chunk IDs".into()));
                    }
                    chunk_ids.push(buf.get_u32_le());
                }
                Self::Want { chunk_ids }
            }
            frame_type::CHUNK => {
                if buf.remaining() < 8 {
                    return Err(Error::Protocol("Incomplete CHUNK frame".into()));
                }
                let chunk_id = buf.get_u32_le();
                let data_len = buf.get_u32_le();

                if buf.remaining() < data_len as usize {
                    return Err(Error::Protocol("Incomplete CHUNK data".into()));
                }
                let data = buf.split_to(data_len as usize).freeze();

                Self::Chunk { chunk_id, data }
            }
            frame_type::CHUNK_BATCH => {
                if buf.remaining() < 4 {
                    return Err(Error::Protocol("Incomplete CHUNK_BATCH frame".into()));
                }
                let count = buf.get_u32_le();
                let mut chunks = Vec::with_capacity(count as usize);

                for _ in 0..count {
                    if buf.remaining() < 8 {
                        return Err(Error::Protocol("Incomplete CHUNK_BATCH entry".into()));
                    }
                    let chunk_id = buf.get_u32_le();
                    let data_len = buf.get_u32_le();

                    if buf.remaining() < data_len as usize {
                        return Err(Error::Protocol("Incomplete CHUNK_BATCH data".into()));
                    }
                    let data = buf.split_to(data_len as usize).freeze();
                    chunks.push((chunk_id, data));
                }

                Self::ChunkBatch { chunks }
            }
            frame_type::SHARD => {
                if buf.remaining() < 12 {
                    return Err(Error::Protocol("Incomplete SHARD frame".into()));
                }
                let chunk_id = buf.get_u32_le();
                let shard_idx = buf.get_u16_le();
                let total_shards = buf.get_u16_le();
                let data_len = buf.get_u32_le();

                if buf.remaining() < data_len as usize {
                    return Err(Error::Protocol("Incomplete SHARD data".into()));
                }
                let data = buf.split_to(data_len as usize).freeze();

                Self::Shard {
                    chunk_id,
                    shard_idx,
                    total_shards,
                    data,
                }
            }
            frame_type::ACK => {
                if buf.remaining() < 4 {
                    return Err(Error::Protocol("Incomplete ACK frame".into()));
                }
                let count = buf.get_u32_le();
                let mut chunk_ids = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    if buf.remaining() < 4 {
                        return Err(Error::Protocol("Incomplete ACK chunk IDs".into()));
                    }
                    chunk_ids.push(buf.get_u32_le());
                }
                Self::Ack { chunk_ids }
            }
            frame_type::NACK => {
                if buf.remaining() < 4 {
                    return Err(Error::Protocol("Incomplete NACK frame".into()));
                }
                let count = buf.get_u32_le();
                let mut chunk_ids = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    if buf.remaining() < 4 {
                        return Err(Error::Protocol("Incomplete NACK chunk IDs".into()));
                    }
                    chunk_ids.push(buf.get_u32_le());
                }

                if buf.remaining() < 4 {
                    return Err(Error::Protocol("Incomplete NACK reason".into()));
                }
                let reason_len = buf.get_u32_le();
                if buf.remaining() < reason_len as usize {
                    return Err(Error::Protocol("Incomplete NACK reason".into()));
                }
                let reason_bytes = buf.split_to(reason_len as usize);
                let reason = std::str::from_utf8(&reason_bytes)
                    .map_err(|e| Error::Protocol(format!("Invalid UTF-8 in NACK reason: {}", e)))?
                    .to_string();

                Self::Nack { chunk_ids, reason }
            }
            frame_type::DONE => Self::Done,
            frame_type::VERIFY => {
                if buf.remaining() < 32 {
                    return Err(Error::Protocol("Incomplete VERIFY frame".into()));
                }
                let mut merkle_root = [0u8; 32];
                buf.copy_to_slice(&mut merkle_root);
                Self::Verify { merkle_root }
            }
            frame_type::CHUNK_VERIFY => {
                // chunk_id (4) + chunk_hash (32) + num_siblings (4) minimum
                if buf.remaining() < 40 {
                    return Err(Error::Protocol("Incomplete CHUNK_VERIFY frame".into()));
                }
                let chunk_id = buf.get_u32_le();
                let mut chunk_hash = [0u8; 32];
                buf.copy_to_slice(&mut chunk_hash);

                let num_siblings = buf.get_u32_le();
                let mut siblings = Vec::with_capacity(num_siblings as usize);
                for _ in 0..num_siblings {
                    if buf.remaining() < 32 {
                        return Err(Error::Protocol("Incomplete CHUNK_VERIFY siblings".into()));
                    }
                    let mut sibling = [0u8; 32];
                    buf.copy_to_slice(&mut sibling);
                    siblings.push(sibling);
                }

                if buf.remaining() < 8 {
                    return Err(Error::Protocol("Incomplete CHUNK_VERIFY proof".into()));
                }
                let leaf_index = buf.get_u32_le();
                let directions_len = buf.get_u32_le();

                if buf.remaining() < directions_len as usize {
                    return Err(Error::Protocol("Incomplete CHUNK_VERIFY directions".into()));
                }
                let directions = buf.split_to(directions_len as usize).to_vec();

                Self::ChunkVerify {
                    chunk_id,
                    chunk_hash,
                    proof: WireMerkleProof {
                        siblings,
                        leaf_index,
                        directions,
                    },
                }
            }
            frame_type::ERROR => {
                if buf.remaining() < 8 {
                    return Err(Error::Protocol("Incomplete ERROR frame".into()));
                }
                let code = buf.get_u32_le();
                let msg_len = buf.get_u32_le();

                if buf.remaining() < msg_len as usize {
                    return Err(Error::Protocol("Incomplete ERROR message".into()));
                }
                let msg_bytes = buf.split_to(msg_len as usize);
                let message = std::str::from_utf8(&msg_bytes)
                    .map_err(|e| Error::Protocol(format!("Invalid UTF-8 in ERROR message: {}", e)))?
                    .to_string();

                Self::Error { code, message }
            }
            frame_type::CANCEL => Self::Cancel,
            frame_type::PAUSE => Self::Pause,
            _ => {
                return Err(Error::Protocol(format!(
                    "Unknown frame type: {}",
                    header.frame_type
                )));
            }
        };

        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_encode_decode() {
        let frame = Frame::Hello { version: 1 };
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let decoded = Frame::decode(&mut buf).unwrap().unwrap();
        match decoded {
            Frame::Hello { version } => assert_eq!(version, 1),
            _ => panic!("Wrong frame type"),
        }
    }

    #[test]
    fn test_chunk_encode_decode() {
        let data = Bytes::from(vec![1u8, 2, 3, 4, 5]);
        let frame = Frame::Chunk {
            chunk_id: 42,
            data: data.clone(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let decoded = Frame::decode(&mut buf).unwrap().unwrap();
        match decoded {
            Frame::Chunk { chunk_id, data: decoded_data } => {
                assert_eq!(chunk_id, 42);
                assert_eq!(decoded_data, data);
            }
            _ => panic!("Wrong frame type"),
        }
    }

    #[test]
    fn test_error_encode_decode() {
        let frame = Frame::Error {
            code: 500,
            message: "Test error".to_string(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let decoded = Frame::decode(&mut buf).unwrap().unwrap();
        match decoded {
            Frame::Error { code, message } => {
                assert_eq!(code, 500);
                assert_eq!(message, "Test error");
            }
            _ => panic!("Wrong frame type"),
        }
    }

    #[test]
    fn test_shard_encode_decode() {
        let data = Bytes::from(vec![10u8, 20, 30, 40, 50]);
        let frame = Frame::Shard {
            chunk_id: 100,
            shard_idx: 3,
            total_shards: 14,
            data: data.clone(),
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let decoded = Frame::decode(&mut buf).unwrap().unwrap();
        match decoded {
            Frame::Shard {
                chunk_id,
                shard_idx,
                total_shards,
                data: decoded_data,
            } => {
                assert_eq!(chunk_id, 100);
                assert_eq!(shard_idx, 3);
                assert_eq!(total_shards, 14);
                assert_eq!(decoded_data, data);
            }
            _ => panic!("Wrong frame type"),
        }
    }

    #[test]
    fn test_chunk_verify_encode_decode() {
        let chunk_hash = [0xABu8; 32];
        let sibling1 = [0x11u8; 32];
        let sibling2 = [0x22u8; 32];
        let proof = WireMerkleProof {
            siblings: vec![sibling1, sibling2],
            leaf_index: 5,
            directions: vec![0b01], // 2 bits packed
        };

        let frame = Frame::ChunkVerify {
            chunk_id: 42,
            chunk_hash,
            proof,
        };

        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();

        let decoded = Frame::decode(&mut buf).unwrap().unwrap();
        match decoded {
            Frame::ChunkVerify {
                chunk_id,
                chunk_hash: decoded_hash,
                proof: decoded_proof,
            } => {
                assert_eq!(chunk_id, 42);
                assert_eq!(decoded_hash, chunk_hash);
                assert_eq!(decoded_proof.siblings.len(), 2);
                assert_eq!(decoded_proof.siblings[0], sibling1);
                assert_eq!(decoded_proof.siblings[1], sibling2);
                assert_eq!(decoded_proof.leaf_index, 5);
                assert_eq!(decoded_proof.directions, vec![0b01]);
            }
            _ => panic!("Wrong frame type"),
        }
    }

    #[test]
    fn test_encoded_size_accuracy() {
        // Test that encoded_size matches actual encoded length
        let frames: Vec<Frame> = vec![
            Frame::Hello { version: 1 },
            Frame::Accept,
            Frame::Done,
            Frame::Cancel,
            Frame::Pause,
            Frame::Chunk {
                chunk_id: 42,
                data: Bytes::from(vec![1u8, 2, 3, 4, 5]),
            },
            Frame::Ack { chunk_ids: vec![1, 2, 3] },
            Frame::Have { chunk_ids: vec![10, 20] },
            Frame::Want { chunk_ids: vec![100] },
            Frame::Nack {
                chunk_ids: vec![5],
                reason: "test error".to_string(),
            },
            Frame::Error {
                code: 500,
                message: "internal error".to_string(),
            },
            Frame::Verify { merkle_root: [0xAB; 32] },
            Frame::Shard {
                chunk_id: 1,
                shard_idx: 2,
                total_shards: 6,
                data: Bytes::from(vec![10u8; 100]),
            },
        ];

        for frame in frames {
            let predicted_size = frame.encoded_size();
            let mut buf = BytesMut::new();
            frame.encode(&mut buf).unwrap();
            let actual_size = buf.len();

            assert_eq!(
                predicted_size, actual_size,
                "Size mismatch for {:?}: predicted {}, actual {}",
                frame.frame_type(), predicted_size, actual_size
            );
        }
    }

    #[test]
    fn test_encode_preallocated() {
        let data = Bytes::from(vec![1u8, 2, 3, 4, 5]);
        let frame = Frame::Chunk {
            chunk_id: 42,
            data: data.clone(),
        };

        // Encode with preallocated buffer
        let buf = frame.encode_preallocated().unwrap();

        // Decode and verify
        let mut buf_clone = buf.clone();
        let decoded = Frame::decode(&mut buf_clone).unwrap().unwrap();
        match decoded {
            Frame::Chunk { chunk_id, data: decoded_data } => {
                assert_eq!(chunk_id, 42);
                assert_eq!(decoded_data, data);
            }
            _ => panic!("Wrong frame type"),
        }

        // Verify capacity matches length (no excess allocation)
        assert_eq!(buf.len(), buf.capacity());
    }
}
