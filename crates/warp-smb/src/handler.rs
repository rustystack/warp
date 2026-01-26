//! SMB command handlers
//!
//! Implements SMB2/3 command processing and dispatch.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Buf, BufMut, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace, warn};

use warp_gateway_common::{InMemoryLockManager, SessionManager};
use warp_store::{ObjectKey, Store};

use crate::config::SmbConfig;
use crate::error::{NtStatus, SmbError, SmbResult};
use crate::oplocks::OplockManager;
use crate::protocol::{
    CreateDisposition, DesiredAccess, FileAttributes, FileId, ShareAccess, Smb2Flags, Smb2Header,
    SmbCommand, SMB2_HEADER_SIZE, SMB2_PROTOCOL_ID,
};
use crate::server::{SessionFlags, SmbSession, TreeConnect};
use crate::share::ShareManager;

/// SMB dialect versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SmbDialect {
    /// SMB 2.0.2
    Smb202 = 0x0202,
    /// SMB 2.1
    Smb210 = 0x0210,
    /// SMB 3.0
    Smb300 = 0x0300,
    /// SMB 3.0.2
    Smb302 = 0x0302,
    /// SMB 3.1.1
    Smb311 = 0x0311,
    /// Wildcard (negotiate any)
    Wildcard = 0x02FF,
}

impl TryFrom<u16> for SmbDialect {
    type Error = NtStatus;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0202 => Ok(Self::Smb202),
            0x0210 => Ok(Self::Smb210),
            0x0300 => Ok(Self::Smb300),
            0x0302 => Ok(Self::Smb302),
            0x0311 => Ok(Self::Smb311),
            0x02FF => Ok(Self::Wildcard),
            _ => Err(NtStatus::InvalidParameter),
        }
    }
}

/// Connection handler for SMB protocol
pub struct SmbConnectionHandler {
    /// Configuration
    config: SmbConfig,
    /// Storage backend
    store: Arc<Store>,
    /// Lock manager
    lock_manager: Arc<InMemoryLockManager>,
    /// Session manager
    _session_manager: Arc<SessionManager>,
    /// Oplock manager
    oplock_manager: Arc<OplockManager>,
    /// Share manager
    share_manager: Arc<ShareManager>,
    /// Current session
    session: Option<SmbSession>,
    /// Negotiated dialect
    dialect: Option<SmbDialect>,
    /// Server GUID
    server_guid: [u8; 16],
    /// Session ID counter
    session_id_counter: AtomicU64,
    /// Tree ID counter
    tree_id_counter: AtomicU32,
    /// Open file handles (FileId -> path)
    open_files: DashMap<FileId, OpenFile>,
    /// File ID counter
    file_id_counter: AtomicU64,
}

/// Open file tracking
struct OpenFile {
    /// File path
    path: String,
    /// Share name
    share_name: String,
    /// Access rights
    access: u32,
    /// Share mode
    share_mode: u32,
    /// Is directory
    is_directory: bool,
}

impl SmbConnectionHandler {
    /// Create a new connection handler
    pub fn new(
        config: SmbConfig,
        store: Arc<Store>,
        lock_manager: Arc<InMemoryLockManager>,
        session_manager: Arc<SessionManager>,
        oplock_manager: Arc<OplockManager>,
        share_manager: Arc<ShareManager>,
    ) -> Self {
        Self {
            server_guid: config.server_guid,
            config,
            store,
            lock_manager,
            _session_manager: session_manager,
            oplock_manager,
            share_manager,
            session: None,
            dialect: None,
            session_id_counter: AtomicU64::new(1),
            tree_id_counter: AtomicU32::new(1),
            open_files: DashMap::new(),
            file_id_counter: AtomicU64::new(1),
        }
    }

    /// Handle a connection
    pub async fn handle_connection(&mut self, mut stream: TcpStream) -> SmbResult<()> {
        debug!("Starting SMB connection handler");

        loop {
            // Read NetBIOS session header (4 bytes)
            let mut nb_header = [0u8; 4];
            match stream.read_exact(&mut nb_header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("Connection closed by peer");
                    break;
                }
                Err(e) => return Err(e.into()),
            }

            // Parse NetBIOS length (24-bit)
            let length = ((nb_header[1] as usize) << 16)
                | ((nb_header[2] as usize) << 8)
                | (nb_header[3] as usize);

            if length < SMB2_HEADER_SIZE {
                warn!("Message too short: {} bytes", length);
                continue;
            }

            // Read SMB message
            let mut message = vec![0u8; length];
            stream.read_exact(&mut message).await?;

            // Parse and process
            let response = match self.process_message(&message).await {
                Ok(resp) => resp,
                Err(e) => {
                    warn!("Error processing message: {}", e);
                    // Create error response
                    self.create_error_response(&message, e)?
                }
            };

            // Send response with NetBIOS header
            let mut response_buf = BytesMut::with_capacity(4 + response.len());
            response_buf.put_u8(0); // NetBIOS session message
            response_buf.put_u8(((response.len() >> 16) & 0xFF) as u8);
            response_buf.put_u8(((response.len() >> 8) & 0xFF) as u8);
            response_buf.put_u8((response.len() & 0xFF) as u8);
            response_buf.extend_from_slice(&response);

            stream.write_all(&response_buf).await?;
        }

        Ok(())
    }

    /// Process an SMB message
    async fn process_message(&mut self, message: &[u8]) -> SmbResult<Vec<u8>> {
        let header = Smb2Header::parse(message)?;
        let body = &message[SMB2_HEADER_SIZE..];

        trace!("Processing {:?} command", header.command);

        match header.command {
            SmbCommand::Negotiate => self.handle_negotiate(&header, body).await,
            SmbCommand::SessionSetup => self.handle_session_setup(&header, body).await,
            SmbCommand::Logoff => self.handle_logoff(&header).await,
            SmbCommand::TreeConnect => self.handle_tree_connect(&header, body).await,
            SmbCommand::TreeDisconnect => self.handle_tree_disconnect(&header).await,
            SmbCommand::Create => self.handle_create(&header, body).await,
            SmbCommand::Close => self.handle_close(&header, body).await,
            SmbCommand::Read => self.handle_read(&header, body).await,
            SmbCommand::Write => self.handle_write(&header, body).await,
            SmbCommand::QueryDirectory => self.handle_query_directory(&header, body).await,
            SmbCommand::QueryInfo => self.handle_query_info(&header, body).await,
            SmbCommand::Echo => self.handle_echo(&header).await,
            _ => {
                debug!("Unsupported command: {:?}", header.command);
                Err(SmbError::NtStatus(NtStatus::NotSupported))
            }
        }
    }

    /// Handle Negotiate command
    async fn handle_negotiate(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 36 {
            return Err(SmbError::Protocol("Negotiate body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let dialect_count = buf.get_u16_le();
        let _security_mode = buf.get_u16_le();
        let _reserved = buf.get_u16_le();
        let capabilities = buf.get_u32_le();

        // Read client GUID
        let mut client_guid = [0u8; 16];
        client_guid.copy_from_slice(&buf[..16]);
        buf.advance(16);

        // Skip negotiate context offset/count for SMB 3.1.1
        buf.advance(8);

        // Read dialects
        let mut dialects = Vec::with_capacity(dialect_count as usize);
        for _ in 0..dialect_count {
            if buf.remaining() < 2 {
                break;
            }
            let d = buf.get_u16_le();
            if let Ok(dialect) = SmbDialect::try_from(d) {
                dialects.push(dialect);
            }
        }

        // Select highest supported dialect
        let selected_dialect = dialects
            .iter()
            .filter(|d| **d != SmbDialect::Wildcard)
            .max_by_key(|d| **d as u16)
            .copied()
            .unwrap_or(SmbDialect::Smb210);

        self.dialect = Some(selected_dialect);
        debug!("Negotiated dialect: {:?}", selected_dialect);

        // Build response
        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(256);
        resp_header.encode(&mut response);

        // Negotiate response body (65 bytes structure)
        response.put_u16_le(65); // StructureSize
        response.put_u16_le(0x01); // SecurityMode (signing enabled)
        response.put_u16_le(selected_dialect as u16);
        response.put_u16_le(0); // NegotiateContextCount
        response.put_slice(&self.server_guid);
        response.put_u32_le(capabilities); // Echo capabilities
        response.put_u32_le(64 * 1024); // MaxTransactSize
        response.put_u32_le(64 * 1024); // MaxReadSize
        response.put_u32_le(64 * 1024); // MaxWriteSize
        response.put_u64_le(0); // SystemTime (TODO: actual time)
        response.put_u64_le(0); // ServerStartTime
        response.put_u16_le(0); // SecurityBufferOffset
        response.put_u16_le(0); // SecurityBufferLength
        response.put_u32_le(0); // NegotiateContextOffset

        Ok(response.to_vec())
    }

    /// Handle SessionSetup command
    async fn handle_session_setup(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 24 {
            return Err(SmbError::Protocol("SessionSetup body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let flags = buf.get_u8();
        let _security_mode = buf.get_u8();
        let _capabilities = buf.get_u32_le();
        let _channel = buf.get_u32_le();
        let _security_buffer_offset = buf.get_u16_le();
        let _security_buffer_length = buf.get_u16_le();
        let _previous_session_id = buf.get_u64_le();

        // Create a new session (simplified - no actual authentication)
        let session_id = self.session_id_counter.fetch_add(1, Ordering::Relaxed);
        let mut client_guid = [0u8; 16];
        // Use a hash of session_id as client guid
        client_guid[0..8].copy_from_slice(&session_id.to_le_bytes());

        let session = SmbSession::new(session_id, client_guid);
        self.session = Some(session);

        debug!("Created session {}", session_id);

        // Build response
        let mut resp_header = Smb2Header::response_from(header, NtStatus::Success);
        resp_header.session_id = session_id;

        let mut response = BytesMut::with_capacity(128);
        resp_header.encode(&mut response);

        // SessionSetup response body
        response.put_u16_le(9); // StructureSize
        response.put_u16_le(if flags & 0x01 != 0 { 0x01 } else { 0x00 }); // SessionFlags
        response.put_u16_le(0); // SecurityBufferOffset
        response.put_u16_le(0); // SecurityBufferLength

        Ok(response.to_vec())
    }

    /// Handle Logoff command
    async fn handle_logoff(&mut self, header: &Smb2Header) -> SmbResult<Vec<u8>> {
        debug!("Session {} logged off", header.session_id);
        self.session = None;

        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 4);
        resp_header.encode(&mut response);

        // Logoff response body
        response.put_u16_le(4); // StructureSize
        response.put_u16_le(0); // Reserved

        Ok(response.to_vec())
    }

    /// Handle TreeConnect command
    async fn handle_tree_connect(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 8 {
            return Err(SmbError::Protocol("TreeConnect body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let _flags = buf.get_u16_le();
        let path_offset = buf.get_u16_le() as usize;
        let path_length = buf.get_u16_le() as usize;

        // Extract share path from the full message
        let share_path_start = path_offset.saturating_sub(SMB2_HEADER_SIZE);
        if share_path_start + path_length > body.len() {
            return Err(SmbError::Protocol("Invalid path offset".to_string()));
        }

        let share_path_bytes = &body[share_path_start..share_path_start + path_length];
        // Convert from UTF-16LE
        let share_path = String::from_utf16_lossy(
            &share_path_bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect::<Vec<_>>(),
        );

        // Extract share name from UNC path (\\server\share)
        let share_name = share_path
            .rsplit('\\')
            .next()
            .unwrap_or(&share_path)
            .to_string();

        debug!("Tree connect to share: {}", share_name);

        // Look up share
        let share = self
            .share_manager
            .get_share(&share_name)
            .ok_or(SmbError::NtStatus(NtStatus::BadNetworkName))?;

        // Create tree connect
        let tree_id = self.tree_id_counter.fetch_add(1, Ordering::Relaxed);
        let tree = TreeConnect {
            tree_id,
            share_name: share_name.clone(),
            share_path: share.bucket.clone(),
            share_type: 0x01, // DISK
            share_flags: 0,
            share_capabilities: 0,
            max_access: 0x001F01FF, // Full access
        };

        // Store in session
        if let Some(ref session) = self.session {
            session.trees.insert(tree_id, tree);
        }

        // Build response
        let mut resp_header = Smb2Header::response_from(header, NtStatus::Success);
        resp_header.tree_id = tree_id;

        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 16);
        resp_header.encode(&mut response);

        // TreeConnect response body
        response.put_u16_le(16); // StructureSize
        response.put_u8(0x01); // ShareType (DISK)
        response.put_u8(0); // Reserved
        response.put_u32_le(0); // ShareFlags
        response.put_u32_le(0); // Capabilities
        response.put_u32_le(0x001F01FF); // MaximalAccess

        Ok(response.to_vec())
    }

    /// Handle TreeDisconnect command
    async fn handle_tree_disconnect(&mut self, header: &Smb2Header) -> SmbResult<Vec<u8>> {
        debug!("Tree {} disconnected", header.tree_id);

        if let Some(ref session) = self.session {
            session.trees.remove(&header.tree_id);
        }

        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 4);
        resp_header.encode(&mut response);

        // TreeDisconnect response body
        response.put_u16_le(4); // StructureSize
        response.put_u16_le(0); // Reserved

        Ok(response.to_vec())
    }

    /// Handle Create (open file) command
    async fn handle_create(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 56 {
            return Err(SmbError::Protocol("Create body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let _security_flags = buf.get_u8();
        let _oplock_level = buf.get_u8();
        let _impersonation_level = buf.get_u32_le();
        let _smb_create_flags = buf.get_u64_le();
        let _reserved = buf.get_u64_le();
        let desired_access = buf.get_u32_le();
        let file_attributes = buf.get_u32_le();
        let share_access = buf.get_u32_le();
        let create_disposition = buf.get_u32_le();
        let create_options = buf.get_u32_le();
        let name_offset = buf.get_u16_le() as usize;
        let name_length = buf.get_u16_le() as usize;

        // Extract file name
        let name_start = name_offset.saturating_sub(SMB2_HEADER_SIZE);
        let file_name = if name_length > 0 && name_start + name_length <= body.len() {
            let name_bytes = &body[name_start..name_start + name_length];
            String::from_utf16_lossy(
                &name_bytes
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                    .collect::<Vec<_>>(),
            )
        } else {
            String::new()
        };

        debug!("Create file: {}", file_name);

        // Get share path from tree connect
        let share_path = if let Some(ref session) = self.session {
            session
                .trees
                .get(&header.tree_id)
                .map(|t| t.share_path.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Build full path
        let full_path = if file_name.is_empty() {
            share_path.clone()
        } else {
            format!("{}/{}", share_path, file_name.replace('\\', "/"))
        };

        // Check if path is a directory (simplified check)
        let is_directory = create_options & 0x01 != 0 || file_name.is_empty();

        // Generate file ID
        let file_id_val = self.file_id_counter.fetch_add(1, Ordering::Relaxed);
        let file_id = FileId::new(file_id_val, file_id_val);

        // Track open file
        self.open_files.insert(
            file_id,
            OpenFile {
                path: full_path.clone(),
                share_name: share_path,
                access: desired_access,
                share_mode: share_access,
                is_directory,
            },
        );

        // Build response
        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 96);
        resp_header.encode(&mut response);

        // Create response body (89 bytes)
        response.put_u16_le(89); // StructureSize
        response.put_u8(0); // OplockLevel
        response.put_u8(0); // Flags
        response.put_u32_le(0x01); // CreateAction (FILE_OPENED)
        response.put_u64_le(0); // CreationTime
        response.put_u64_le(0); // LastAccessTime
        response.put_u64_le(0); // LastWriteTime
        response.put_u64_le(0); // ChangeTime
        response.put_u64_le(0); // AllocationSize
        response.put_u64_le(0); // EndOfFile
        response.put_u32_le(if is_directory {
            FileAttributes::DIRECTORY
        } else {
            FileAttributes::NORMAL
        }); // FileAttributes
        response.put_u32_le(0); // Reserved2
        file_id.encode(&mut response);
        response.put_u32_le(0); // CreateContextsOffset
        response.put_u32_le(0); // CreateContextsLength

        Ok(response.to_vec())
    }

    /// Handle Close command
    async fn handle_close(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 24 {
            return Err(SmbError::Protocol("Close body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let _flags = buf.get_u16_le();
        let _reserved = buf.get_u32_le();
        let file_id = FileId::parse(&mut &buf[..16]);

        debug!("Close file: {:?}", file_id);

        // Remove from tracking
        self.open_files.remove(&file_id);

        // Build response
        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 60);
        resp_header.encode(&mut response);

        // Close response body (60 bytes)
        response.put_u16_le(60); // StructureSize
        response.put_u16_le(0); // Flags
        response.put_u32_le(0); // Reserved
        response.put_u64_le(0); // CreationTime
        response.put_u64_le(0); // LastAccessTime
        response.put_u64_le(0); // LastWriteTime
        response.put_u64_le(0); // ChangeTime
        response.put_u64_le(0); // AllocationSize
        response.put_u64_le(0); // EndOfFile
        response.put_u32_le(FileAttributes::NORMAL); // FileAttributes

        Ok(response.to_vec())
    }

    /// Handle Read command
    async fn handle_read(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 48 {
            return Err(SmbError::Protocol("Read body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let _padding = buf.get_u8();
        let _flags = buf.get_u8();
        let length = buf.get_u32_le();
        let offset = buf.get_u64_le();
        let file_id = FileId::parse(&mut &buf[..16]);
        buf.advance(16);
        let _minimum_count = buf.get_u32_le();
        let _channel = buf.get_u32_le();
        let _remaining_bytes = buf.get_u32_le();

        debug!("Read {} bytes at offset {} from {:?}", length, offset, file_id);

        // Get file info
        let file_info = self
            .open_files
            .get(&file_id)
            .ok_or(SmbError::NtStatus(NtStatus::InvalidHandle))?;

        // Read from store using ObjectKey
        let data = if let Some((bucket, key)) = self.parse_path(&file_info.path) {
            let object_key = ObjectKey::new(&bucket, &key);
            match self.store.get(&object_key).await {
                Ok(object_data) => {
                    let full_data = object_data.data.to_vec();
                    let start = offset as usize;
                    let end = (start + length as usize).min(full_data.len());
                    if start < full_data.len() {
                        full_data[start..end].to_vec()
                    } else {
                        vec![]
                    }
                }
                Err(_) => vec![],
            }
        } else {
            vec![]
        };

        let data_length = data.len() as u32;

        // Build response
        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 17 + data.len());
        resp_header.encode(&mut response);

        // Read response body
        response.put_u16_le(17); // StructureSize
        response.put_u8(80); // DataOffset (SMB2_HEADER_SIZE + 16)
        response.put_u8(0); // Reserved
        response.put_u32_le(data_length); // DataLength
        response.put_u32_le(0); // DataRemaining
        response.put_u32_le(0); // Reserved2

        // Padding to data offset
        let padding = 80 - (SMB2_HEADER_SIZE + 16);
        response.put_bytes(0, padding);

        // Append data
        response.extend_from_slice(&data);

        Ok(response.to_vec())
    }

    /// Handle Write command
    async fn handle_write(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 48 {
            return Err(SmbError::Protocol("Write body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let data_offset = buf.get_u16_le() as usize;
        let length = buf.get_u32_le();
        let offset = buf.get_u64_le();
        let file_id = FileId::parse(&mut &buf[..16]);

        debug!("Write {} bytes at offset {} to {:?}", length, offset, file_id);

        // Get file info
        let file_info = self
            .open_files
            .get(&file_id)
            .ok_or(SmbError::NtStatus(NtStatus::InvalidHandle))?;

        // Extract data from the full message body
        let data_start = data_offset.saturating_sub(SMB2_HEADER_SIZE);
        let write_data = if data_start + (length as usize) <= body.len() {
            &body[data_start..data_start + (length as usize)]
        } else {
            &[]
        };

        // Write to store using ObjectKey
        let bytes_written = if let Some((bucket, key)) = self.parse_path(&file_info.path) {
            let object_key = ObjectKey::new(&bucket, &key);
            // For simplicity, we're doing a full overwrite. A proper implementation
            // would support partial writes with read-modify-write semantics
            let object_data = warp_store::ObjectData {
                data: bytes::Bytes::copy_from_slice(write_data),
                content_type: Some("application/octet-stream".to_string()),
                metadata: Default::default(),
            };
            match self.store.put(&object_key, object_data).await {
                Ok(_) => write_data.len(),
                Err(_) => 0,
            }
        } else {
            0
        };

        // Build response
        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 16);
        resp_header.encode(&mut response);

        // Write response body
        response.put_u16_le(17); // StructureSize
        response.put_u16_le(0); // Reserved
        response.put_u32_le(bytes_written as u32); // Count
        response.put_u32_le(0); // Remaining
        response.put_u16_le(0); // WriteChannelInfoOffset
        response.put_u16_le(0); // WriteChannelInfoLength

        Ok(response.to_vec())
    }

    /// Handle QueryDirectory command
    async fn handle_query_directory(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 32 {
            return Err(SmbError::Protocol("QueryDirectory body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let info_class = buf.get_u8();
        let flags = buf.get_u8();
        let _file_index = buf.get_u32_le();
        let file_id = FileId::parse(&mut &buf[..16]);
        buf.advance(16);
        let _file_name_offset = buf.get_u16_le();
        let _file_name_length = buf.get_u16_le();
        let output_buffer_length = buf.get_u32_le();

        debug!(
            "QueryDirectory: info_class={}, flags={}, file_id={:?}",
            info_class, flags, file_id
        );

        // Get directory info
        let _file_info = self
            .open_files
            .get(&file_id)
            .ok_or(SmbError::NtStatus(NtStatus::InvalidHandle))?;

        // For now, return no more files (simplified)
        let resp_header = Smb2Header::response_from(header, NtStatus::NoMoreFiles);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 8);
        resp_header.encode(&mut response);

        // QueryDirectory response body
        response.put_u16_le(9); // StructureSize
        response.put_u16_le(0); // OutputBufferOffset
        response.put_u32_le(0); // OutputBufferLength

        Ok(response.to_vec())
    }

    /// Handle QueryInfo command
    async fn handle_query_info(
        &mut self,
        header: &Smb2Header,
        body: &[u8],
    ) -> SmbResult<Vec<u8>> {
        if body.len() < 40 {
            return Err(SmbError::Protocol("QueryInfo body too short".to_string()));
        }

        let mut buf = body;
        let _structure_size = buf.get_u16_le();
        let info_type = buf.get_u8();
        let file_info_class = buf.get_u8();
        let _output_buffer_length = buf.get_u32_le();
        let _input_buffer_offset = buf.get_u16_le();
        let _reserved = buf.get_u16_le();
        let _input_buffer_length = buf.get_u32_le();
        let _additional_information = buf.get_u32_le();
        let _flags = buf.get_u32_le();
        let file_id = FileId::parse(&mut &buf[..16]);

        debug!(
            "QueryInfo: type={}, class={}, file_id={:?}",
            info_type, file_info_class, file_id
        );

        // Get file info
        let file_info = self
            .open_files
            .get(&file_id)
            .ok_or(SmbError::NtStatus(NtStatus::InvalidHandle))?;

        // Build response based on info type and class
        let info_data = self.build_file_info(info_type, file_info_class, &file_info)?;

        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 8 + info_data.len());
        resp_header.encode(&mut response);

        // QueryInfo response body
        response.put_u16_le(9); // StructureSize
        response.put_u16_le(72); // OutputBufferOffset
        response.put_u32_le(info_data.len() as u32); // OutputBufferLength

        // Padding to offset
        let padding = 72 - (SMB2_HEADER_SIZE + 8);
        response.put_bytes(0, padding);

        response.extend_from_slice(&info_data);

        Ok(response.to_vec())
    }

    /// Build file info response data
    fn build_file_info(
        &self,
        info_type: u8,
        file_info_class: u8,
        file_info: &dashmap::mapref::one::Ref<'_, FileId, OpenFile>,
    ) -> SmbResult<Vec<u8>> {
        let mut data = BytesMut::new();

        match (info_type, file_info_class) {
            // FILE_INFO, FileBasicInformation
            (1, 4) => {
                data.put_u64_le(0); // CreationTime
                data.put_u64_le(0); // LastAccessTime
                data.put_u64_le(0); // LastWriteTime
                data.put_u64_le(0); // ChangeTime
                data.put_u32_le(if file_info.is_directory {
                    FileAttributes::DIRECTORY
                } else {
                    FileAttributes::NORMAL
                }); // FileAttributes
                data.put_u32_le(0); // Reserved
            }
            // FILE_INFO, FileStandardInformation
            (1, 5) => {
                data.put_u64_le(0); // AllocationSize
                data.put_u64_le(0); // EndOfFile
                data.put_u32_le(1); // NumberOfLinks
                data.put_u8(0); // DeletePending
                data.put_u8(if file_info.is_directory { 1 } else { 0 }); // Directory
                data.put_u16_le(0); // Reserved
            }
            // FILE_INFO, FileAllInformation
            (1, 18) => {
                // Basic info
                data.put_u64_le(0); // CreationTime
                data.put_u64_le(0); // LastAccessTime
                data.put_u64_le(0); // LastWriteTime
                data.put_u64_le(0); // ChangeTime
                data.put_u32_le(if file_info.is_directory {
                    FileAttributes::DIRECTORY
                } else {
                    FileAttributes::NORMAL
                });
                data.put_u32_le(0); // Reserved

                // Standard info
                data.put_u64_le(0); // AllocationSize
                data.put_u64_le(0); // EndOfFile
                data.put_u32_le(1); // NumberOfLinks
                data.put_u8(0); // DeletePending
                data.put_u8(if file_info.is_directory { 1 } else { 0 });
                data.put_u16_le(0); // Reserved

                // Internal info
                data.put_u64_le(0); // IndexNumber

                // EA info
                data.put_u32_le(0); // EaSize

                // Access info
                data.put_u32_le(file_info.access);

                // Position info
                data.put_u64_le(0); // CurrentByteOffset

                // Mode info
                data.put_u32_le(0); // Mode

                // Alignment info
                data.put_u32_le(0); // AlignmentRequirement

                // Name info
                data.put_u32_le(0); // FileNameLength
            }
            _ => {
                // Return basic info for unknown types
                data.put_u64_le(0); // CreationTime
                data.put_u64_le(0); // LastAccessTime
                data.put_u64_le(0); // LastWriteTime
                data.put_u64_le(0); // ChangeTime
                data.put_u32_le(FileAttributes::NORMAL);
                data.put_u32_le(0);
            }
        }

        Ok(data.to_vec())
    }

    /// Handle Echo command
    async fn handle_echo(&mut self, header: &Smb2Header) -> SmbResult<Vec<u8>> {
        let resp_header = Smb2Header::response_from(header, NtStatus::Success);
        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 4);
        resp_header.encode(&mut response);

        // Echo response body
        response.put_u16_le(4); // StructureSize
        response.put_u16_le(0); // Reserved

        Ok(response.to_vec())
    }

    /// Parse a path into (bucket, key) components
    fn parse_path(&self, path: &str) -> Option<(String, String)> {
        let path = path.trim_start_matches('/');
        let mut parts = path.splitn(2, '/');
        let bucket = parts.next()?.to_string();
        let key = parts.next().unwrap_or("").to_string();
        if bucket.is_empty() {
            None
        } else {
            Some((bucket, key))
        }
    }

    /// Create an error response
    fn create_error_response(&self, message: &[u8], error: SmbError) -> SmbResult<Vec<u8>> {
        let status = match error {
            SmbError::NtStatus(s) => s,
            SmbError::AccessDenied => NtStatus::AccessDenied,
            SmbError::ShareNotFound(_) => NtStatus::BadNetworkName,
            SmbError::FileNotFound(_) => NtStatus::ObjectNameNotFound,
            SmbError::NotSupported(_) => NtStatus::NotSupported,
            _ => NtStatus::InvalidParameter,
        };

        let header = Smb2Header::parse(message)?;
        let resp_header = Smb2Header::response_from(&header, status);

        let mut response = BytesMut::with_capacity(SMB2_HEADER_SIZE + 8);
        resp_header.encode(&mut response);

        // Error response body
        response.put_u16_le(9); // StructureSize
        response.put_u8(0); // ErrorContextCount
        response.put_u8(0); // Reserved
        response.put_u32_le(0); // ByteCount

        Ok(response.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_dialect() {
        assert_eq!(SmbDialect::try_from(0x0311).unwrap(), SmbDialect::Smb311);
        assert_eq!(SmbDialect::try_from(0x0210).unwrap(), SmbDialect::Smb210);
    }

    #[test]
    fn test_smb_dialect_all_versions() {
        assert_eq!(SmbDialect::try_from(0x0202).unwrap(), SmbDialect::Smb202);
        assert_eq!(SmbDialect::try_from(0x0300).unwrap(), SmbDialect::Smb300);
        assert_eq!(SmbDialect::try_from(0x0302).unwrap(), SmbDialect::Smb302);
        assert_eq!(SmbDialect::try_from(0x02FF).unwrap(), SmbDialect::Wildcard);
        assert!(SmbDialect::try_from(0x0100).is_err());
    }

    #[test]
    fn test_file_id_creation() {
        let file_id = FileId::new(123, 456);
        assert_eq!(file_id.persistent, 123);
        assert_eq!(file_id.volatile, 456);
        assert_ne!(file_id, FileId::INVALID);
    }

    #[test]
    fn test_smb2_header_response() {
        let request = Smb2Header::new_request(SmbCommand::Read, 1, 100, 1);
        let response = Smb2Header::response_from(&request, NtStatus::Success);

        assert!(response.flags.is_response());
        assert_eq!(response.message_id, 1);
        assert_eq!(response.session_id, 100);
        assert_eq!(response.command, SmbCommand::Read);
    }
}
