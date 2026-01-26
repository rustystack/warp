//! XDR (External Data Representation) encoding/decoding
//!
//! Implements RFC 4506 XDR encoding for NFS protocol types.

use bytes::{BufMut, Bytes, BytesMut};
use std::io;

/// XDR encoder
pub struct XdrEncoder {
    buf: BytesMut,
}

impl XdrEncoder {
    /// Create a new encoder with default capacity
    pub fn new() -> Self {
        Self::with_capacity(1024)
    }

    /// Create a new encoder with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
        }
    }

    /// Encode a 32-bit integer
    pub fn encode_u32(&mut self, value: u32) {
        self.buf.put_u32(value);
    }

    /// Encode a 64-bit integer
    pub fn encode_u64(&mut self, value: u64) {
        self.buf.put_u64(value);
    }

    /// Encode a 32-bit signed integer
    pub fn encode_i32(&mut self, value: i32) {
        self.buf.put_i32(value);
    }

    /// Encode a boolean
    pub fn encode_bool(&mut self, value: bool) {
        self.encode_u32(if value { 1 } else { 0 });
    }

    /// Encode a variable-length opaque (bytes)
    pub fn encode_opaque(&mut self, data: &[u8]) {
        self.encode_u32(data.len() as u32);
        self.buf.put_slice(data);
        // Pad to 4-byte boundary
        let padding = (4 - (data.len() % 4)) % 4;
        for _ in 0..padding {
            self.buf.put_u8(0);
        }
    }

    /// Encode a fixed-length opaque
    pub fn encode_opaque_fixed(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
        // Pad to 4-byte boundary
        let padding = (4 - (data.len() % 4)) % 4;
        for _ in 0..padding {
            self.buf.put_u8(0);
        }
    }

    /// Encode a string
    pub fn encode_string(&mut self, s: &str) {
        self.encode_opaque(s.as_bytes());
    }

    /// Get the encoded bytes
    pub fn finish(self) -> Bytes {
        self.buf.freeze()
    }

    /// Get current length
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for XdrEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// XDR decoder
pub struct XdrDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> XdrDecoder<'a> {
    /// Create a new decoder
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Get remaining bytes
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Decode a 32-bit integer
    pub fn decode_u32(&mut self) -> io::Result<u32> {
        if self.remaining() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data for u32",
            ));
        }
        let value = u32::from_be_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(value)
    }

    /// Decode a 64-bit integer
    pub fn decode_u64(&mut self) -> io::Result<u64> {
        if self.remaining() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data for u64",
            ));
        }
        let value = u64::from_be_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(value)
    }

    /// Decode a 32-bit signed integer
    pub fn decode_i32(&mut self) -> io::Result<i32> {
        self.decode_u32().map(|v| v as i32)
    }

    /// Decode a boolean
    pub fn decode_bool(&mut self) -> io::Result<bool> {
        self.decode_u32().map(|v| v != 0)
    }

    /// Decode a variable-length opaque
    pub fn decode_opaque(&mut self) -> io::Result<Vec<u8>> {
        let len = self.decode_u32()? as usize;
        let padded_len = (len + 3) & !3; // Round up to 4-byte boundary

        if self.remaining() < padded_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data for opaque",
            ));
        }

        let data = self.data[self.pos..self.pos + len].to_vec();
        self.pos += padded_len;
        Ok(data)
    }

    /// Decode a fixed-length opaque
    pub fn decode_opaque_fixed(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let padded_len = (len + 3) & !3;

        if self.remaining() < padded_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data for fixed opaque",
            ));
        }

        let data = self.data[self.pos..self.pos + len].to_vec();
        self.pos += padded_len;
        Ok(data)
    }

    /// Decode a string
    pub fn decode_string(&mut self) -> io::Result<String> {
        let bytes = self.decode_opaque()?;
        String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Skip bytes
    pub fn skip(&mut self, n: usize) -> io::Result<()> {
        if self.remaining() < n {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data to skip",
            ));
        }
        self.pos += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_u32() {
        let mut enc = XdrEncoder::new();
        enc.encode_u32(0x12345678);
        let data = enc.finish();

        let mut dec = XdrDecoder::new(&data);
        assert_eq!(dec.decode_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_encode_decode_string() {
        let mut enc = XdrEncoder::new();
        enc.encode_string("hello");
        let data = enc.finish();

        let mut dec = XdrDecoder::new(&data);
        assert_eq!(dec.decode_string().unwrap(), "hello");
    }

    #[test]
    fn test_encode_decode_opaque() {
        let mut enc = XdrEncoder::new();
        enc.encode_opaque(&[1, 2, 3, 4, 5]);
        let data = enc.finish();

        let mut dec = XdrDecoder::new(&data);
        assert_eq!(dec.decode_opaque().unwrap(), vec![1, 2, 3, 4, 5]);
    }
}
