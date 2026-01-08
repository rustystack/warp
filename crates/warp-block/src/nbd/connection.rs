//! NBD connection handler
//!
//! Handles the NBD protocol for a single client connection.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, trace, warn};

use super::{
    ClientFlags, ExportInfo, GlobalFlags, NBD_INIT_MAGIC, NBD_OPTS_MAGIC, NBD_REP_MAGIC,
    NbdCommand, NbdOption, NbdReply, NbdReplyType, NbdRequest, TransmissionFlags,
};
use crate::error::{BlockError, BlockResult, NbdError};

/// NBD connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state - waiting for handshake
    Initial,
    /// Option negotiation phase
    OptionNegotiation,
    /// Transmission phase - handling commands
    Transmission,
    /// Connection closed
    Closed,
}

/// Volume I/O trait for NBD operations
#[async_trait]
pub trait VolumeIO: Send + Sync {
    /// Read data from the volume
    async fn read(&self, offset: u64, length: u32) -> BlockResult<Vec<u8>>;
    /// Write data to the volume
    async fn write(&self, offset: u64, data: &[u8]) -> BlockResult<()>;
    /// Flush pending writes
    async fn flush(&self) -> BlockResult<()>;
    /// Trim/discard a range
    async fn trim(&self, offset: u64, length: u32) -> BlockResult<()>;
    /// Write zeros to a range
    async fn write_zeroes(&self, offset: u64, length: u32, fast: bool) -> BlockResult<()>;
}

/// NBD connection handler
pub struct NbdConnection {
    stream: TcpStream,
    state: ConnectionState,
    client_flags: ClientFlags,
    structured_reply: bool,
    export: Option<ExportInfo>,
}

impl NbdConnection {
    /// Create a new connection handler
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: ConnectionState::Initial,
            client_flags: ClientFlags::new(0),
            structured_reply: false,
            export: None,
        }
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Run the connection handler with a volume provider
    pub async fn run<V: VolumeIO>(
        mut self,
        exports: &[ExportInfo],
        get_volume: impl Fn(&str) -> Option<Arc<V>>,
    ) -> BlockResult<()> {
        // Phase 1: Initial handshake
        self.send_server_greeting().await?;
        self.receive_client_flags().await?;
        self.state = ConnectionState::OptionNegotiation;

        // Phase 2: Option negotiation
        let volume: Arc<V>;
        loop {
            match self.handle_option(exports).await? {
                OptionResult::Continue => continue,
                OptionResult::GoToTransmission(name) => {
                    volume = get_volume(&name)
                        .ok_or_else(|| BlockError::VolumeNotFound(name.clone()))?;
                    self.state = ConnectionState::Transmission;
                    break;
                }
                OptionResult::Abort => {
                    self.state = ConnectionState::Closed;
                    return Ok(());
                }
            }
        }

        // Phase 3: Transmission
        info!(
            "Entering transmission phase for export: {:?}",
            self.export.as_ref().map(|e| &e.name)
        );
        self.run_transmission_loop(&*volume).await
    }

    /// Send server greeting (newstyle negotiation)
    async fn send_server_greeting(&mut self) -> BlockResult<()> {
        let mut buf = BytesMut::with_capacity(18);
        buf.put_u64(NBD_INIT_MAGIC);
        buf.put_u64(NBD_OPTS_MAGIC);
        buf.put_u16(GlobalFlags::server_default().bits());

        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;
        debug!("Sent server greeting");
        Ok(())
    }

    /// Receive client flags
    async fn receive_client_flags(&mut self) -> BlockResult<()> {
        let flags = self.stream.read_u32().await?;
        self.client_flags = ClientFlags::new(flags);
        debug!("Received client flags: {:08x}", flags);
        Ok(())
    }

    /// Handle an option request
    async fn handle_option(&mut self, exports: &[ExportInfo]) -> BlockResult<OptionResult> {
        let magic = self.stream.read_u64().await?;
        if magic != NBD_OPTS_MAGIC {
            return Err(BlockError::Protocol(format!(
                "Invalid option magic: {:016x}",
                magic
            )));
        }

        let option_code = self.stream.read_u32().await?;
        let data_len = self.stream.read_u32().await?;

        let mut data = vec![0u8; data_len as usize];
        if data_len > 0 {
            self.stream.read_exact(&mut data).await?;
        }

        trace!("Received option: {} (data len: {})", option_code, data_len);

        match NbdOption::try_from(option_code) {
            Ok(NbdOption::ExportName) => {
                let name = String::from_utf8_lossy(&data).to_string();
                self.handle_export_name(&name, exports).await
            }
            Ok(NbdOption::Abort) => {
                debug!("Client requested abort");
                Ok(OptionResult::Abort)
            }
            Ok(NbdOption::List) => {
                self.send_export_list(exports).await?;
                Ok(OptionResult::Continue)
            }
            Ok(NbdOption::Info) => {
                self.handle_info(&data, exports).await?;
                Ok(OptionResult::Continue)
            }
            Ok(NbdOption::Go) => {
                let name = String::from_utf8_lossy(&data).to_string();
                self.handle_go(&name, exports).await
            }
            Ok(NbdOption::StructuredReply) => {
                self.structured_reply = true;
                self.send_option_reply(option_code, NbdReplyType::Ack, &[])
                    .await?;
                debug!("Enabled structured replies");
                Ok(OptionResult::Continue)
            }
            _ => {
                self.send_option_reply(option_code, NbdReplyType::ErrUnsup, &[])
                    .await?;
                Ok(OptionResult::Continue)
            }
        }
    }

    /// Handle NBD_OPT_EXPORT_NAME
    async fn handle_export_name(
        &mut self,
        name: &str,
        exports: &[ExportInfo],
    ) -> BlockResult<OptionResult> {
        let export = exports
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| BlockError::VolumeNotFound(name.to_string()))?;

        // Send export info (oldstyle response)
        let mut buf = BytesMut::with_capacity(10);
        buf.put_u64(export.size);
        buf.put_u16(export.flags.bits());

        if self.client_flags.bits() & ClientFlags::NO_ZEROES == 0 {
            buf.put_bytes(0, 124);
        }

        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;

        self.export = Some(export.clone());
        info!("Client connected to export: {}", name);
        Ok(OptionResult::GoToTransmission(name.to_string()))
    }

    /// Handle NBD_OPT_GO
    async fn handle_go(&mut self, name: &str, exports: &[ExportInfo]) -> BlockResult<OptionResult> {
        let export = exports.iter().find(|e| e.name == name);

        match export {
            Some(export) => {
                self.send_export_info_reply(NbdOption::Go as u32, export)
                    .await?;
                self.send_option_reply(NbdOption::Go as u32, NbdReplyType::Ack, &[])
                    .await?;

                self.export = Some(export.clone());
                info!("Client connected to export via GO: {}", name);
                Ok(OptionResult::GoToTransmission(name.to_string()))
            }
            None => {
                self.send_option_reply(NbdOption::Go as u32, NbdReplyType::ErrUnknown, &[])
                    .await?;
                Ok(OptionResult::Continue)
            }
        }
    }

    /// Handle NBD_OPT_INFO
    async fn handle_info(&mut self, data: &[u8], exports: &[ExportInfo]) -> BlockResult<()> {
        let name = String::from_utf8_lossy(data).to_string();
        let export = exports.iter().find(|e| e.name == name);

        match export {
            Some(export) => {
                self.send_export_info_reply(NbdOption::Info as u32, export)
                    .await?;
                self.send_option_reply(NbdOption::Info as u32, NbdReplyType::Ack, &[])
                    .await?;
            }
            None => {
                self.send_option_reply(NbdOption::Info as u32, NbdReplyType::ErrUnknown, &[])
                    .await?;
            }
        }
        Ok(())
    }

    /// Send export list
    async fn send_export_list(&mut self, exports: &[ExportInfo]) -> BlockResult<()> {
        for export in exports {
            let name_bytes = export.name.as_bytes();
            let mut data = BytesMut::with_capacity(4 + name_bytes.len());
            data.put_u32(name_bytes.len() as u32);
            data.put_slice(name_bytes);
            self.send_option_reply(NbdOption::List as u32, NbdReplyType::Server, &data)
                .await?;
        }
        self.send_option_reply(NbdOption::List as u32, NbdReplyType::Ack, &[])
            .await?;
        Ok(())
    }

    /// Send export info reply
    async fn send_export_info_reply(
        &mut self,
        option: u32,
        export: &ExportInfo,
    ) -> BlockResult<()> {
        // NBD_INFO_EXPORT
        let mut data = BytesMut::with_capacity(12);
        data.put_u16(0);
        data.put_u64(export.size);
        data.put_u16(export.flags.bits());
        self.send_option_reply(option, NbdReplyType::Info, &data)
            .await?;

        // NBD_INFO_BLOCK_SIZE
        let mut data = BytesMut::with_capacity(14);
        data.put_u16(3);
        data.put_u32(export.min_block_size);
        data.put_u32(export.preferred_block_size);
        data.put_u32(export.max_block_size);
        self.send_option_reply(option, NbdReplyType::Info, &data)
            .await?;

        Ok(())
    }

    /// Send option reply
    async fn send_option_reply(
        &mut self,
        option: u32,
        reply_type: NbdReplyType,
        data: &[u8],
    ) -> BlockResult<()> {
        let mut buf = BytesMut::with_capacity(20 + data.len());
        buf.put_u64(NBD_REP_MAGIC);
        buf.put_u32(option);
        buf.put_u32(reply_type as u32);
        buf.put_u32(data.len() as u32);
        buf.put_slice(data);

        self.stream.write_all(&buf).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Run the transmission loop
    async fn run_transmission_loop<V: VolumeIO>(&mut self, volume: &V) -> BlockResult<()> {
        let mut request_buf = [0u8; NbdRequest::SIZE];
        let export = self.export.clone().unwrap();

        loop {
            match self.stream.read_exact(&mut request_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("Client disconnected");
                    break;
                }
                Err(e) => return Err(e.into()),
            }

            let request = NbdRequest::parse(&request_buf)?;
            trace!(
                "Request: {:?} offset={} len={}",
                request.command, request.offset, request.length
            );

            match self.handle_command(&request, volume, &export).await {
                Ok(true) => continue,
                Ok(false) => {
                    debug!("Client requested disconnect");
                    break;
                }
                Err(e) => {
                    warn!("Command failed: {}", e);
                    self.send_reply(request.handle, e.to_nbd_error()).await?;
                }
            }
        }

        self.state = ConnectionState::Closed;
        Ok(())
    }

    /// Handle a command
    async fn handle_command<V: VolumeIO>(
        &mut self,
        request: &NbdRequest,
        volume: &V,
        export: &ExportInfo,
    ) -> BlockResult<bool> {
        match request.command {
            NbdCommand::Read => {
                self.handle_read(request, volume, export).await?;
                Ok(true)
            }
            NbdCommand::Write => {
                self.handle_write(request, volume, export).await?;
                Ok(true)
            }
            NbdCommand::Disc => Ok(false),
            NbdCommand::Flush => {
                volume.flush().await?;
                self.send_reply(request.handle, NbdError::Ok).await?;
                Ok(true)
            }
            NbdCommand::Trim => {
                self.handle_trim(request, volume, export).await?;
                Ok(true)
            }
            NbdCommand::WriteZeroes => {
                self.handle_write_zeroes(request, volume, export).await?;
                Ok(true)
            }
            NbdCommand::Cache => {
                self.send_reply(request.handle, NbdError::Ok).await?;
                Ok(true)
            }
            _ => {
                self.send_reply(request.handle, NbdError::NotSup).await?;
                Ok(true)
            }
        }
    }

    /// Handle read command
    async fn handle_read<V: VolumeIO>(
        &mut self,
        request: &NbdRequest,
        volume: &V,
        export: &ExportInfo,
    ) -> BlockResult<()> {
        if request.offset + request.length as u64 > export.size {
            return Err(BlockError::InvalidOffset {
                offset: request.offset,
                size: export.size,
            });
        }

        let data = volume.read(request.offset, request.length).await?;

        let reply = NbdReply::ok(request.handle);
        let mut buf = BytesMut::with_capacity(NbdReply::SIZE + data.len());
        reply.encode(&mut buf);
        buf.put_slice(&data);

        self.stream.write_all(&buf).await?;
        Ok(())
    }

    /// Handle write command
    async fn handle_write<V: VolumeIO>(
        &mut self,
        request: &NbdRequest,
        volume: &V,
        export: &ExportInfo,
    ) -> BlockResult<()> {
        if export.flags.bits() & TransmissionFlags::READ_ONLY != 0 {
            let mut discard = vec![0u8; request.length as usize];
            self.stream.read_exact(&mut discard).await?;
            return Err(BlockError::ReadOnly);
        }

        if request.offset + request.length as u64 > export.size {
            let mut discard = vec![0u8; request.length as usize];
            self.stream.read_exact(&mut discard).await?;
            return Err(BlockError::InvalidOffset {
                offset: request.offset,
                size: export.size,
            });
        }

        let mut data = vec![0u8; request.length as usize];
        self.stream.read_exact(&mut data).await?;

        volume.write(request.offset, &data).await?;

        if request.flags.has_fua() {
            volume.flush().await?;
        }

        self.send_reply(request.handle, NbdError::Ok).await
    }

    /// Handle trim command
    async fn handle_trim<V: VolumeIO>(
        &mut self,
        request: &NbdRequest,
        volume: &V,
        export: &ExportInfo,
    ) -> BlockResult<()> {
        if request.offset + request.length as u64 > export.size {
            return Err(BlockError::InvalidOffset {
                offset: request.offset,
                size: export.size,
            });
        }

        volume.trim(request.offset, request.length).await?;
        self.send_reply(request.handle, NbdError::Ok).await
    }

    /// Handle write zeroes command
    async fn handle_write_zeroes<V: VolumeIO>(
        &mut self,
        request: &NbdRequest,
        volume: &V,
        export: &ExportInfo,
    ) -> BlockResult<()> {
        if export.flags.bits() & TransmissionFlags::READ_ONLY != 0 {
            return Err(BlockError::ReadOnly);
        }

        if request.offset + request.length as u64 > export.size {
            return Err(BlockError::InvalidOffset {
                offset: request.offset,
                size: export.size,
            });
        }

        volume
            .write_zeroes(
                request.offset,
                request.length,
                request.flags.has_fast_zero(),
            )
            .await?;

        if request.flags.has_fua() {
            volume.flush().await?;
        }

        self.send_reply(request.handle, NbdError::Ok).await
    }

    /// Send a reply
    async fn send_reply(&mut self, handle: u64, error: NbdError) -> BlockResult<()> {
        let reply = NbdReply::new(handle, error);
        let mut buf = BytesMut::with_capacity(NbdReply::SIZE);
        reply.encode(&mut buf);
        self.stream.write_all(&buf).await?;
        Ok(())
    }
}

/// Result of option handling
enum OptionResult {
    Continue,
    GoToTransmission(String),
    Abort,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::net::TcpListener;

    /// Test volume implementation
    struct TestVolume {
        size: u64,
        data: parking_lot::RwLock<Vec<u8>>,
        flush_count: AtomicU64,
    }

    impl TestVolume {
        fn new(size: u64) -> Self {
            Self {
                size,
                data: parking_lot::RwLock::new(vec![0u8; size as usize]),
                flush_count: AtomicU64::new(0),
            }
        }
    }

    #[async_trait]
    impl VolumeIO for TestVolume {
        async fn read(&self, offset: u64, length: u32) -> BlockResult<Vec<u8>> {
            let data = self.data.read();
            let start = offset as usize;
            let end = start + length as usize;
            if end > data.len() {
                return Err(BlockError::InvalidOffset {
                    offset,
                    size: self.size,
                });
            }
            Ok(data[start..end].to_vec())
        }

        async fn write(&self, offset: u64, data: &[u8]) -> BlockResult<()> {
            let mut storage = self.data.write();
            let start = offset as usize;
            let end = start + data.len();
            if end > storage.len() {
                return Err(BlockError::InvalidOffset {
                    offset,
                    size: self.size,
                });
            }
            storage[start..end].copy_from_slice(data);
            Ok(())
        }

        async fn flush(&self) -> BlockResult<()> {
            self.flush_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn trim(&self, offset: u64, length: u32) -> BlockResult<()> {
            let mut storage = self.data.write();
            let start = offset as usize;
            let end = start + length as usize;
            if end > storage.len() {
                return Err(BlockError::InvalidOffset {
                    offset,
                    size: self.size,
                });
            }
            storage[start..end].fill(0);
            Ok(())
        }

        async fn write_zeroes(&self, offset: u64, length: u32, _fast: bool) -> BlockResult<()> {
            self.trim(offset, length).await
        }
    }

    #[test]
    fn test_connection_state() {
        assert_eq!(ConnectionState::Initial, ConnectionState::Initial);
        assert_ne!(ConnectionState::Initial, ConnectionState::Transmission);
    }

    #[tokio::test]
    async fn test_volume_io_read_write() {
        let volume = TestVolume::new(4096);

        // Write some data
        let data = b"hello world";
        volume.write(0, data).await.unwrap();

        // Read it back
        let result = volume.read(0, data.len() as u32).await.unwrap();
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_volume_io_trim() {
        let volume = TestVolume::new(4096);

        // Write some data
        volume.write(0, &[0xFF; 100]).await.unwrap();

        // Trim it
        volume.trim(0, 100).await.unwrap();

        // Should be zeros
        let result = volume.read(0, 100).await.unwrap();
        assert!(result.iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn test_volume_io_flush() {
        let volume = TestVolume::new(4096);

        volume.flush().await.unwrap();
        volume.flush().await.unwrap();

        assert_eq!(volume.flush_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_volume_io_bounds_check() {
        let volume = TestVolume::new(100);

        // Read past end should fail
        let result = volume.read(50, 100).await;
        assert!(result.is_err());

        // Write past end should fail
        let result = volume.write(50, &[0; 100]).await;
        assert!(result.is_err());
    }
}
