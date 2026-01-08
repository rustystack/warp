//! NVMe-oF Connection Management
//!
//! This module handles NVMe-oF connections, including the connection
//! lifecycle, command processing, and state management.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use tracing::{debug, info, trace, warn};

use super::capsule::{
    CommandCapsule, ConnectData, ControllerCapabilities, ControllerConfiguration, ControllerStatus,
    PropertyOffset, ResponseCapsule,
};
use super::command::{
    AdminOpcode, FabricsType, FeatureId, IdentifyCns, IdentifyController, IdentifyNamespace,
    IoOpcode, NvmeCommand, NvmeCompletion,
};
use super::config::NvmeOfConfig;
use super::error::{NvmeOfError, NvmeOfResult, NvmeStatus};
use super::queue::QueueManager;
use super::transport::{ConnectionState, TransportConnection};

/// Controller ID
pub type ControllerId = u16;

/// NVMe-oF Connection
///
/// Represents a single connection from a host to the NVMe-oF target.
/// Each connection has its own controller instance.
pub struct NvmeOfConnection {
    /// Connection ID (unique per target)
    id: u64,

    /// Controller ID (assigned during connect)
    cntlid: AtomicU16,

    /// Transport connection
    transport: Arc<dyn TransportConnection>,

    /// Queue manager
    queues: QueueManager,

    /// Connection state
    state: RwLock<ConnectionState>,

    /// Host NQN
    host_nqn: RwLock<String>,

    /// Subsystem NQN (what the host connected to)
    subsystem_nqn: RwLock<String>,

    /// Host ID
    host_id: RwLock<[u8; 16]>,

    /// Controller capabilities
    capabilities: ControllerCapabilities,

    /// Controller configuration
    configuration: RwLock<ControllerConfiguration>,

    /// Controller status
    status: RwLock<ControllerStatus>,

    /// Keep-alive timeout (ms)
    keep_alive_timeout: u32,

    /// Last activity timestamp
    last_activity: RwLock<Instant>,

    /// Connection active flag
    active: AtomicBool,

    /// Number of I/O queues allocated
    num_io_queues: AtomicU16,

    /// Async event manager
    async_events: AsyncEventManager,

    /// Statistics
    stats: RwLock<ConnectionStats>,
}

impl NvmeOfConnection {
    /// Create a new connection
    pub fn new(id: u64, transport: Arc<dyn TransportConnection>, config: &NvmeOfConfig) -> Self {
        Self {
            id,
            cntlid: AtomicU16::new(0xFFFF),
            transport,
            queues: QueueManager::new(config.max_queues_per_connection, config.max_queue_depth),
            state: RwLock::new(ConnectionState::Connecting),
            host_nqn: RwLock::new(String::new()),
            subsystem_nqn: RwLock::new(String::new()),
            host_id: RwLock::new([0u8; 16]),
            capabilities: ControllerCapabilities::warp_defaults(),
            configuration: RwLock::new(ControllerConfiguration::default()),
            status: RwLock::new(ControllerStatus::default()),
            keep_alive_timeout: config.keep_alive_timeout_ms,
            last_activity: RwLock::new(Instant::now()),
            active: AtomicBool::new(true),
            num_io_queues: AtomicU16::new(0),
            async_events: AsyncEventManager::new(4),
            stats: RwLock::new(ConnectionStats::default()),
        }
    }

    /// Get connection ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get controller ID
    pub fn cntlid(&self) -> ControllerId {
        self.cntlid.load(Ordering::Relaxed)
    }

    /// Set controller ID
    pub fn set_cntlid(&self, cntlid: ControllerId) {
        self.cntlid.store(cntlid, Ordering::Relaxed);
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Set connection state
    pub fn set_state(&self, state: ConnectionState) {
        *self.state.write() = state;
    }

    /// Get remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.transport.remote_addr()
    }

    /// Get host NQN
    pub fn host_nqn(&self) -> String {
        self.host_nqn.read().clone()
    }

    /// Get subsystem NQN
    pub fn subsystem_nqn(&self) -> String {
        self.subsystem_nqn.read().clone()
    }

    /// Check if connection is active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed) && self.transport.is_connected()
    }

    /// Update last activity timestamp
    pub fn touch(&self) {
        *self.last_activity.write() = Instant::now();
    }

    /// Check if connection has timed out
    pub fn is_timed_out(&self) -> bool {
        let timeout_ms = self.keep_alive_timeout as u64;
        if timeout_ms == 0 {
            return false;
        }

        let last = *self.last_activity.read();
        last.elapsed() > Duration::from_millis(timeout_ms)
    }

    /// Get queue manager
    pub fn queues(&self) -> &QueueManager {
        &self.queues
    }

    /// Get transport connection
    pub fn transport(&self) -> &Arc<dyn TransportConnection> {
        &self.transport
    }

    /// Process a received command capsule
    pub async fn process_command(
        &self,
        capsule: CommandCapsule,
        namespace_handler: &dyn NamespaceHandler,
    ) -> NvmeOfResult<ResponseCapsule> {
        self.touch();
        self.stats.write().commands_received += 1;

        let cmd = &capsule.command;
        let cid = cmd.cid();
        let opcode = cmd.opcode();

        trace!(
            "Processing command: opcode={:#04x}, cid={}, nsid={}",
            opcode, cid, cmd.nsid
        );

        // Check if it's a fabrics command
        if cmd.is_fabrics() {
            return self.handle_fabrics_command(capsule).await;
        }

        // Check if it's an admin command (queue 0)
        if cmd.nsid == 0 || opcode >= 0x80 {
            return self.handle_admin_command(capsule).await;
        }

        // It's an I/O command
        self.handle_io_command(capsule, namespace_handler).await
    }

    /// Handle Fabrics-specific commands
    async fn handle_fabrics_command(
        &self,
        capsule: CommandCapsule,
    ) -> NvmeOfResult<ResponseCapsule> {
        let cmd = &capsule.command;
        let cid = cmd.cid();
        let fctype = cmd.fctype();

        match FabricsType::from_raw(fctype) {
            Some(FabricsType::Connect) => self.handle_connect(capsule).await,
            Some(FabricsType::PropertyGet) => self.handle_property_get(cmd).await,
            Some(FabricsType::PropertySet) => self.handle_property_set(cmd).await,
            Some(FabricsType::Disconnect) => self.handle_disconnect().await,
            _ => {
                warn!("Unknown fabrics command type: {:#04x}", fctype);
                Ok(ResponseCapsule::error(
                    cid,
                    0,
                    self.queues.admin().sq_head(),
                    NvmeStatus::InvalidOpcode,
                ))
            }
        }
    }

    /// Handle Fabrics Connect command
    async fn handle_connect(&self, capsule: CommandCapsule) -> NvmeOfResult<ResponseCapsule> {
        let cmd = &capsule.command;
        let cid = cmd.cid();

        // Connect data should be in capsule data
        let data = capsule.data.as_ref().ok_or_else(|| {
            NvmeOfError::InvalidCapsule("Connect command missing data".to_string())
        })?;

        let connect_data = ConnectData::from_bytes(data)?;

        // Store host info
        *self.host_nqn.write() = connect_data.hostnqn_str().to_string();
        *self.subsystem_nqn.write() = connect_data.subnqn_str().to_string();
        *self.host_id.write() = connect_data.hostid;

        // Assign controller ID if not specified
        let cntlid = if connect_data.cntlid == 0xFFFF {
            // Dynamic allocation - use low bits of connection ID
            (self.id & 0xFFFF) as u16
        } else {
            connect_data.cntlid
        };
        self.set_cntlid(cntlid);

        // Update state
        self.set_state(ConnectionState::Ready);
        *self.status.write() = ControllerStatus::ready();

        info!(
            "Connection {} established: host={}, subsystem={}, cntlid={}",
            self.id,
            connect_data.hostnqn_str(),
            connect_data.subnqn_str(),
            cntlid
        );

        // Return success with controller ID in result
        let mut completion = NvmeCompletion::success(cid, 0, self.queues.admin().sq_head());
        completion.result = cntlid as u32;

        Ok(ResponseCapsule::new(completion))
    }

    /// Handle Property Get command
    async fn handle_property_get(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let offset = cmd.cdw10;
        let _size_8byte = (cmd.cdw11 & 0x01) != 0;

        let value = match PropertyOffset::from_raw(offset) {
            Some(PropertyOffset::Cap) => self.capabilities.to_u64(),
            Some(PropertyOffset::Vs) => 0x00010400, // NVMe 1.4
            Some(PropertyOffset::Cc) => self.configuration.read().to_u32() as u64,
            Some(PropertyOffset::Csts) => self.status.read().to_u32() as u64,
            Some(PropertyOffset::Nssr) => 0,
            None => {
                return Ok(ResponseCapsule::error(
                    cid,
                    0,
                    self.queues.admin().sq_head(),
                    NvmeStatus::InvalidField,
                ));
            }
        };

        let mut completion = NvmeCompletion::success(cid, 0, self.queues.admin().sq_head());
        completion.result = (value & 0xFFFFFFFF) as u32;

        Ok(ResponseCapsule::new(completion))
    }

    /// Handle Property Set command
    async fn handle_property_set(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let offset = cmd.cdw10;
        let value = ((cmd.cdw12 as u64) << 32) | (cmd.cdw11 as u64);

        match PropertyOffset::from_raw(offset) {
            Some(PropertyOffset::Cc) => {
                let cc = ControllerConfiguration::from_u32(value as u32);
                *self.configuration.write() = cc;

                // Update status based on CC.EN
                if cc.en {
                    self.status.write().rdy = true;
                } else {
                    self.status.write().rdy = false;
                }

                debug!("Controller configuration updated: EN={}", cc.en);
            }
            Some(PropertyOffset::Nssr) => {
                // NVM subsystem reset - no-op for now
                debug!("NVM subsystem reset requested");
            }
            _ => {
                return Ok(ResponseCapsule::error(
                    cid,
                    0,
                    self.queues.admin().sq_head(),
                    NvmeStatus::InvalidField,
                ));
            }
        }

        Ok(ResponseCapsule::success(
            cid,
            0,
            self.queues.admin().sq_head(),
        ))
    }

    /// Handle Disconnect command
    async fn handle_disconnect(&self) -> NvmeOfResult<ResponseCapsule> {
        info!("Disconnect requested for connection {}", self.id);
        self.active.store(false, Ordering::Relaxed);
        self.set_state(ConnectionState::Closing);

        Ok(ResponseCapsule::success(
            0,
            0,
            self.queues.admin().sq_head(),
        ))
    }

    /// Handle Admin commands
    async fn handle_admin_command(&self, capsule: CommandCapsule) -> NvmeOfResult<ResponseCapsule> {
        let cmd = &capsule.command;
        let cid = cmd.cid();
        let sq_head = self.queues.admin().sq_head();

        match AdminOpcode::from_raw(cmd.opcode()) {
            Some(AdminOpcode::Identify) => self.handle_identify(cmd).await,
            Some(AdminOpcode::GetFeatures) => self.handle_get_features(cmd).await,
            Some(AdminOpcode::SetFeatures) => self.handle_set_features(cmd).await,
            Some(AdminOpcode::CreateIoCq) => self.handle_create_io_cq(cmd).await,
            Some(AdminOpcode::CreateIoSq) => self.handle_create_io_sq(cmd).await,
            Some(AdminOpcode::DeleteIoCq) => self.handle_delete_io_cq(cmd).await,
            Some(AdminOpcode::DeleteIoSq) => self.handle_delete_io_sq(cmd).await,
            Some(AdminOpcode::KeepAlive) => {
                self.touch();
                Ok(ResponseCapsule::success(cid, 0, sq_head))
            }
            Some(AdminOpcode::AsyncEventRequest) => self.handle_async_event_request(cmd).await,
            _ => {
                warn!("Unsupported admin command: {:#04x}", cmd.opcode());
                Ok(ResponseCapsule::error(
                    cid,
                    0,
                    sq_head,
                    NvmeStatus::InvalidOpcode,
                ))
            }
        }
    }

    /// Handle Identify command
    async fn handle_identify(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let cns = cmd.identify_cns();
        let sq_head = self.queues.admin().sq_head();

        let data = match IdentifyCns::from_raw(cns) {
            Some(IdentifyCns::Controller) => {
                let ctrl = IdentifyController::warp_defaults(
                    self.cntlid(),
                    256, // Max namespaces
                    &self.subsystem_nqn(),
                );
                ctrl.to_bytes()
            }
            Some(IdentifyCns::Namespace) => {
                // Return namespace info (placeholder - real impl uses namespace handler)
                let ns = IdentifyNamespace::new(
                    1024 * 1024 * 1024, // 1GB
                    4096,               // 4KB blocks
                );
                ns.to_bytes()
            }
            Some(IdentifyCns::ActiveNamespaceList) => {
                // Return list of active namespace IDs
                let mut data = vec![0u8; 4096];
                // Add namespace ID 1 (little-endian u32)
                data[0..4].copy_from_slice(&1u32.to_le_bytes());
                Bytes::from(data)
            }
            _ => {
                return Ok(ResponseCapsule::error(
                    cid,
                    0,
                    sq_head,
                    NvmeStatus::InvalidField,
                ));
            }
        };

        let completion = NvmeCompletion::success(cid, 0, sq_head);
        Ok(ResponseCapsule::with_data(completion, data))
    }

    /// Handle Get Features command
    async fn handle_get_features(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let fid = cmd.feature_id();
        let sq_head = self.queues.admin().sq_head();

        let result = match FeatureId::from_raw(fid) {
            Some(FeatureId::NumberOfQueues) => {
                // Return max I/O queues supported (both SQ and CQ counts)
                let nsq = self.queues.max_queues() - 1; // Excluding admin
                let ncq = self.queues.max_queues() - 1;
                ((ncq as u32) << 16) | (nsq as u32)
            }
            Some(FeatureId::KeepAliveTimer) => {
                // Return keep-alive timeout in 100ms units
                self.keep_alive_timeout / 100
            }
            Some(FeatureId::VolatileWriteCache) => {
                1 // Enabled
            }
            _ => {
                return Ok(ResponseCapsule::error(
                    cid,
                    0,
                    sq_head,
                    NvmeStatus::InvalidField,
                ));
            }
        };

        let mut completion = NvmeCompletion::success(cid, 0, sq_head);
        completion.result = result;
        Ok(ResponseCapsule::new(completion))
    }

    /// Handle Set Features command
    async fn handle_set_features(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let fid = cmd.feature_id();
        let sq_head = self.queues.admin().sq_head();

        match FeatureId::from_raw(fid) {
            Some(FeatureId::NumberOfQueues) => {
                let nsq_requested = (cmd.cdw11 & 0xFFFF) as u16;
                let ncq_requested = ((cmd.cdw11 >> 16) & 0xFFFF) as u16;

                let max = self.queues.max_queues() - 1;
                let nsq = nsq_requested.min(max);
                let ncq = ncq_requested.min(max);

                self.num_io_queues.store(nsq.min(ncq), Ordering::Relaxed);

                let mut completion = NvmeCompletion::success(cid, 0, sq_head);
                completion.result = ((ncq as u32) << 16) | (nsq as u32);
                return Ok(ResponseCapsule::new(completion));
            }
            Some(FeatureId::KeepAliveTimer) => {
                // Accept but ignore - we use our configured timeout
                return Ok(ResponseCapsule::success(cid, 0, sq_head));
            }
            _ => {
                // Unknown feature - return error
            }
        }

        Ok(ResponseCapsule::error(
            cid,
            0,
            sq_head,
            NvmeStatus::InvalidField,
        ))
    }

    /// Handle Async Event Request
    ///
    /// AER commands are queued until an event occurs. When an event happens,
    /// a pending AER is completed with the event information.
    async fn handle_async_event_request(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let sq_head = self.queues.admin().sq_head();

        // Check if there's a queued event that we can satisfy immediately
        if let Some(event) = self.async_events.try_get_queued_event(cid) {
            self.stats.write().async_events_posted += 1;
            debug!(
                cid = cid,
                event_type = ?event.event_type,
                "Async event request immediately satisfied"
            );

            let mut completion = NvmeCompletion::success(cid, 0, sq_head);
            completion.result = event.to_result();
            return Ok(ResponseCapsule::new(completion));
        }

        // AER queued, waiting for an event - don't return a completion yet
        // In a real implementation, this would be deferred until an event occurs
        // For now, we return success immediately (the host will resubmit)
        debug!(cid = cid, "Async event request queued");
        Ok(ResponseCapsule::success(cid, 0, sq_head))
    }

    /// Post an async event to this connection
    ///
    /// If there's a pending AER, returns a response capsule to send.
    /// Otherwise, the event is queued for a future AER.
    pub fn post_async_event(&self, event: AsyncEvent) -> Option<ResponseCapsule> {
        if let Some((cid, event)) = self.async_events.post_event(event) {
            self.stats.write().async_events_posted += 1;
            debug!(
                cid = cid,
                event_type = ?event.event_type,
                "Posting async event"
            );

            let sq_head = self.queues.admin().sq_head();
            let mut completion = NvmeCompletion::success(cid, 0, sq_head);
            completion.result = event.to_result();
            return Some(ResponseCapsule::new(completion));
        }
        None
    }

    /// Post a namespace changed event
    pub fn post_namespace_changed(&self) -> Option<ResponseCapsule> {
        self.post_async_event(AsyncEvent::namespace_changed())
    }

    /// Post an error event
    pub fn post_error_event(&self, info: AsyncEventErrorInfo) -> Option<ResponseCapsule> {
        self.post_async_event(AsyncEvent::error(info))
    }

    /// Post a SMART/health event
    pub fn post_smart_event(&self, info: AsyncEventSmartInfo) -> Option<ResponseCapsule> {
        self.post_async_event(AsyncEvent::smart(info))
    }

    /// Get the async event manager
    pub fn async_event_manager(&self) -> &AsyncEventManager {
        &self.async_events
    }

    /// Handle Create I/O Completion Queue
    async fn handle_create_io_cq(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let qid = (cmd.cdw10 & 0xFFFF) as u16;
        let qsize = ((cmd.cdw10 >> 16) & 0xFFFF) as u16;
        let sq_head = self.queues.admin().sq_head();

        if qid == 0 {
            return Ok(ResponseCapsule::error(
                cid,
                0,
                sq_head,
                NvmeStatus::InvalidField,
            ));
        }

        // For NVMe-oF, CQ and SQ are paired, so we just validate
        debug!("Create I/O CQ: qid={}, size={}", qid, qsize + 1);

        Ok(ResponseCapsule::success(cid, 0, sq_head))
    }

    /// Handle Create I/O Submission Queue
    async fn handle_create_io_sq(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let qid = (cmd.cdw10 & 0xFFFF) as u16;
        let qsize = ((cmd.cdw10 >> 16) & 0xFFFF) as u16;
        let sq_head = self.queues.admin().sq_head();

        if qid == 0 {
            return Ok(ResponseCapsule::error(
                cid,
                0,
                sq_head,
                NvmeStatus::InvalidField,
            ));
        }

        self.queues.create_io_queue(qid, qsize + 1)?;
        debug!("Create I/O SQ: qid={}, size={}", qid, qsize + 1);

        Ok(ResponseCapsule::success(cid, 0, sq_head))
    }

    /// Handle Delete I/O Completion Queue
    async fn handle_delete_io_cq(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let qid = (cmd.cdw10 & 0xFFFF) as u16;
        let sq_head = self.queues.admin().sq_head();

        if qid == 0 {
            return Ok(ResponseCapsule::error(
                cid,
                0,
                sq_head,
                NvmeStatus::InvalidField,
            ));
        }

        debug!("Delete I/O CQ: qid={}", qid);
        Ok(ResponseCapsule::success(cid, 0, sq_head))
    }

    /// Handle Delete I/O Submission Queue
    async fn handle_delete_io_sq(&self, cmd: &NvmeCommand) -> NvmeOfResult<ResponseCapsule> {
        let cid = cmd.cid();
        let qid = (cmd.cdw10 & 0xFFFF) as u16;
        let sq_head = self.queues.admin().sq_head();

        if qid == 0 {
            return Ok(ResponseCapsule::error(
                cid,
                0,
                sq_head,
                NvmeStatus::InvalidField,
            ));
        }

        self.queues.delete_io_queue(qid)?;
        debug!("Delete I/O SQ: qid={}", qid);
        Ok(ResponseCapsule::success(cid, 0, sq_head))
    }

    /// Handle I/O commands
    async fn handle_io_command(
        &self,
        capsule: CommandCapsule,
        namespace_handler: &dyn NamespaceHandler,
    ) -> NvmeOfResult<ResponseCapsule> {
        let cmd = &capsule.command;
        let cid = cmd.cid();
        let nsid = cmd.nsid;
        let sq_head = self.queues.admin().sq_head();

        match IoOpcode::from_raw(cmd.opcode()) {
            Some(IoOpcode::Read) => {
                let slba = cmd.slba();
                let nlb = cmd.nlb() as u32 + 1;

                let data = namespace_handler.read(nsid, slba, nlb).await?;

                let completion = NvmeCompletion::success(cid, 0, sq_head);
                self.stats.write().bytes_read += data.len() as u64;
                Ok(ResponseCapsule::with_data(completion, data))
            }
            Some(IoOpcode::Write) => {
                let slba = cmd.slba();
                let nlb = cmd.nlb() as u32 + 1;

                let data = capsule.data.unwrap_or_default();
                namespace_handler
                    .write(nsid, slba, nlb, data.clone())
                    .await?;

                self.stats.write().bytes_written += data.len() as u64;
                Ok(ResponseCapsule::success(cid, 0, sq_head))
            }
            Some(IoOpcode::Flush) => {
                namespace_handler.flush(nsid).await?;
                Ok(ResponseCapsule::success(cid, 0, sq_head))
            }
            Some(IoOpcode::WriteZeroes) => {
                let slba = cmd.slba();
                let nlb = cmd.nlb() as u32 + 1;
                namespace_handler.write_zeroes(nsid, slba, nlb).await?;
                Ok(ResponseCapsule::success(cid, 0, sq_head))
            }
            Some(IoOpcode::DatasetManagement) => {
                // TRIM/Deallocate
                let slba = cmd.slba();
                let nlb = cmd.nlb() as u32 + 1;
                namespace_handler.trim(nsid, slba, nlb).await?;
                Ok(ResponseCapsule::success(cid, 0, sq_head))
            }
            _ => {
                warn!("Unsupported I/O command: {:#04x}", cmd.opcode());
                Ok(ResponseCapsule::error(
                    cid,
                    0,
                    sq_head,
                    NvmeStatus::InvalidOpcode,
                ))
            }
        }
    }

    /// Send a response to the host
    pub async fn send_response(&self, response: ResponseCapsule) -> NvmeOfResult<()> {
        self.stats.write().responses_sent += 1;
        self.transport.send_response(&response).await
    }

    /// Close the connection
    pub async fn close(&self) -> NvmeOfResult<()> {
        info!("Closing connection {}", self.id);
        self.active.store(false, Ordering::Relaxed);
        self.set_state(ConnectionState::Closed);
        self.transport.close().await
    }

    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStats {
        self.stats.read().clone()
    }
}

/// Namespace handler trait for I/O operations
#[async_trait]
pub trait NamespaceHandler: Send + Sync {
    /// Read data from namespace
    async fn read(&self, nsid: u32, slba: u64, nlb: u32) -> NvmeOfResult<Bytes>;

    /// Write data to namespace
    async fn write(&self, nsid: u32, slba: u64, nlb: u32, data: Bytes) -> NvmeOfResult<()>;

    /// Flush namespace
    async fn flush(&self, nsid: u32) -> NvmeOfResult<()>;

    /// Write zeroes
    async fn write_zeroes(&self, nsid: u32, slba: u64, nlb: u32) -> NvmeOfResult<()>;

    /// TRIM/Deallocate
    async fn trim(&self, nsid: u32, slba: u64, nlb: u32) -> NvmeOfResult<()>;

    /// Get namespace size in blocks
    async fn size(&self, nsid: u32) -> NvmeOfResult<u64>;

    /// Get namespace block size
    async fn block_size(&self, nsid: u32) -> NvmeOfResult<u32>;
}

/// NVMe Async Event Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AsyncEventType {
    /// Error status event
    Error = 0,
    /// SMART/Health event
    Smart = 1,
    /// Notice event
    Notice = 2,
    /// I/O Command Set Specific
    IoCommandSet = 6,
    /// Vendor Specific
    VendorSpecific = 7,
}

impl AsyncEventType {
    /// Get the event type bits
    pub fn bits(&self) -> u8 {
        *self as u8
    }
}

/// NVMe Async Event Info - Error events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AsyncEventErrorInfo {
    /// Invalid doorbell write value
    InvalidDoorbellWrite = 0,
    /// Invalid doorbell register
    InvalidDoorbellRegister = 1,
    /// Diagnostic failure
    DiagnosticFailure = 2,
    /// Persistent internal error
    PersistentInternalError = 3,
    /// Transient internal error
    TransientInternalError = 4,
    /// Firmware image load error
    FirmwareImageLoadError = 5,
}

/// NVMe Async Event Info - SMART/Health events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AsyncEventSmartInfo {
    /// NVM subsystem reliability
    Reliability = 0,
    /// Temperature threshold
    Temperature = 1,
    /// Spare below threshold
    SpareBelowThreshold = 2,
}

/// NVMe Async Event Info - Notice events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AsyncEventNoticeInfo {
    /// Namespace attribute changed
    NamespaceAttributeChanged = 0,
    /// Firmware activation starting
    FirmwareActivationStarting = 1,
    /// Telemetry log changed
    TelemetryLogChanged = 2,
    /// Asymmetric namespace access change
    AsymmetricAccessChange = 3,
    /// Predictable latency event aggregate log change
    LatencyLogChange = 4,
    /// LBA status information alert
    LbaStatusAlert = 5,
    /// Endurance group event aggregate log change
    EnduranceGroupLogChange = 6,
    /// Normal NVM subsystem shutdown
    NormalShutdown = 0xF,
}

/// Async event with full information
#[derive(Debug, Clone, Copy)]
pub struct AsyncEvent {
    /// Event type
    pub event_type: AsyncEventType,
    /// Event info (type-specific)
    pub event_info: u8,
    /// Log page identifier (for retrieving more info)
    pub log_page: u8,
}

impl AsyncEvent {
    /// Create an error event
    pub fn error(info: AsyncEventErrorInfo) -> Self {
        Self {
            event_type: AsyncEventType::Error,
            event_info: info as u8,
            log_page: 0x01, // Error Information Log
        }
    }

    /// Create a SMART/Health event
    pub fn smart(info: AsyncEventSmartInfo) -> Self {
        Self {
            event_type: AsyncEventType::Smart,
            event_info: info as u8,
            log_page: 0x02, // SMART Log
        }
    }

    /// Create a notice event
    pub fn notice(info: AsyncEventNoticeInfo) -> Self {
        Self {
            event_type: AsyncEventType::Notice,
            event_info: info as u8,
            log_page: match info {
                AsyncEventNoticeInfo::NamespaceAttributeChanged => 0x0C, // Changed NS List
                AsyncEventNoticeInfo::FirmwareActivationStarting => 0x03, // Firmware Slot
                _ => 0x00,
            },
        }
    }

    /// Create a namespace attribute changed event
    pub fn namespace_changed() -> Self {
        Self::notice(AsyncEventNoticeInfo::NamespaceAttributeChanged)
    }

    /// Encode to completion result (dword 0)
    pub fn to_result(&self) -> u32 {
        let event_type = self.event_type.bits() as u32;
        let event_info = self.event_info as u32;
        let log_page = self.log_page as u32;

        // Format: [31:24] Log Page | [23:16] Reserved | [15:8] Event Info | [7:3] Reserved | [2:0] Event Type
        (log_page << 24) | (event_info << 8) | event_type
    }
}

/// Async event manager for tracking pending AERs and events
pub struct AsyncEventManager {
    /// Pending AER commands (waiting for events)
    pending_aers: RwLock<VecDeque<u16>>, // CIDs of pending AER commands
    /// Queued events (waiting for AER commands)
    queued_events: RwLock<VecDeque<AsyncEvent>>,
    /// Event configuration bitmask
    event_config: AtomicU32,
    /// Maximum pending AERs (per NVMe spec, should be at least 4)
    max_pending_aers: u32,
}

impl AsyncEventManager {
    /// Create a new async event manager
    pub fn new(max_pending_aers: u32) -> Self {
        Self {
            pending_aers: RwLock::new(VecDeque::with_capacity(max_pending_aers as usize)),
            queued_events: RwLock::new(VecDeque::with_capacity(64)),
            event_config: AtomicU32::new(0xFFFFFFFF), // All events enabled by default
            max_pending_aers,
        }
    }

    /// Queue an AER request (returns true if queued, false if limit reached)
    pub fn queue_aer(&self, cid: u16) -> bool {
        let mut pending = self.pending_aers.write();
        if pending.len() >= self.max_pending_aers as usize {
            return false;
        }
        pending.push_back(cid);
        true
    }

    /// Post an async event (returns CID if an AER was satisfied)
    pub fn post_event(&self, event: AsyncEvent) -> Option<(u16, AsyncEvent)> {
        // Check if this event type is enabled
        let config = self.event_config.load(Ordering::Relaxed);
        let type_mask = 1u32 << event.event_type.bits();
        if config & type_mask == 0 {
            return None;
        }

        // Try to find a pending AER to satisfy
        let mut pending = self.pending_aers.write();
        if let Some(cid) = pending.pop_front() {
            return Some((cid, event));
        }

        // No pending AER - queue the event
        let mut queued = self.queued_events.write();
        if queued.len() < 64 {
            queued.push_back(event);
        }
        None
    }

    /// Try to get a queued event for a new AER (returns event if available)
    pub fn try_get_queued_event(&self, cid: u16) -> Option<AsyncEvent> {
        let mut queued = self.queued_events.write();
        if let Some(event) = queued.pop_front() {
            return Some(event);
        }

        // No queued events - add CID to pending
        let mut pending = self.pending_aers.write();
        if pending.len() < self.max_pending_aers as usize {
            pending.push_back(cid);
        }
        None
    }

    /// Set event configuration
    pub fn set_config(&self, config: u32) {
        self.event_config.store(config, Ordering::Relaxed);
    }

    /// Get event configuration
    pub fn get_config(&self) -> u32 {
        self.event_config.load(Ordering::Relaxed)
    }

    /// Get count of pending AERs
    pub fn pending_count(&self) -> usize {
        self.pending_aers.read().len()
    }

    /// Get count of queued events
    pub fn queued_event_count(&self) -> usize {
        self.queued_events.read().len()
    }

    /// Clear all pending AERs (on controller reset)
    pub fn clear(&self) {
        self.pending_aers.write().clear();
        self.queued_events.write().clear();
    }
}

impl Default for AsyncEventManager {
    fn default() -> Self {
        Self::new(4) // NVMe spec recommends at least 4
    }
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Commands received
    pub commands_received: u64,

    /// Responses sent
    pub responses_sent: u64,

    /// Bytes read
    pub bytes_read: u64,

    /// Bytes written
    pub bytes_written: u64,

    /// Errors
    pub errors: u64,

    /// Async events posted
    pub async_events_posted: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.commands_received, 0);
        assert_eq!(stats.bytes_read, 0);
        assert_eq!(stats.async_events_posted, 0);
    }

    #[test]
    fn test_async_event_encoding() {
        // Test error event encoding
        let event = AsyncEvent::error(AsyncEventErrorInfo::DiagnosticFailure);
        let result = event.to_result();
        assert_eq!(result & 0x7, 0); // Event type = Error = 0
        assert_eq!((result >> 8) & 0xFF, 2); // Event info = DiagnosticFailure = 2
        assert_eq!((result >> 24) & 0xFF, 0x01); // Log page = Error log

        // Test SMART event encoding
        let event = AsyncEvent::smart(AsyncEventSmartInfo::Temperature);
        let result = event.to_result();
        assert_eq!(result & 0x7, 1); // Event type = Smart = 1
        assert_eq!((result >> 8) & 0xFF, 1); // Event info = Temperature = 1
        assert_eq!((result >> 24) & 0xFF, 0x02); // Log page = SMART log

        // Test notice event encoding
        let event = AsyncEvent::namespace_changed();
        let result = event.to_result();
        assert_eq!(result & 0x7, 2); // Event type = Notice = 2
        assert_eq!((result >> 8) & 0xFF, 0); // Event info = NamespaceChanged = 0
        assert_eq!((result >> 24) & 0xFF, 0x0C); // Log page = Changed NS List
    }

    #[test]
    fn test_async_event_manager_basic() {
        let mgr = AsyncEventManager::new(4);

        // Initially empty
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.queued_event_count(), 0);

        // Queue AERs
        assert!(mgr.queue_aer(1));
        assert!(mgr.queue_aer(2));
        assert!(mgr.queue_aer(3));
        assert!(mgr.queue_aer(4));
        assert!(!mgr.queue_aer(5)); // Should fail - limit reached

        assert_eq!(mgr.pending_count(), 4);
    }

    #[test]
    fn test_async_event_manager_post_event() {
        let mgr = AsyncEventManager::new(4);

        // Queue an AER
        assert!(mgr.queue_aer(42));

        // Post an event - should satisfy the pending AER
        let event = AsyncEvent::namespace_changed();
        let result = mgr.post_event(event);
        assert!(result.is_some());
        let (cid, _) = result.unwrap();
        assert_eq!(cid, 42);

        // No more pending AERs
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_async_event_manager_queue_event() {
        let mgr = AsyncEventManager::new(4);

        // No pending AERs - event should be queued
        let event = AsyncEvent::namespace_changed();
        let result = mgr.post_event(event);
        assert!(result.is_none()); // No pending AER

        assert_eq!(mgr.queued_event_count(), 1);

        // New AER should immediately get the queued event
        let queued = mgr.try_get_queued_event(100);
        assert!(queued.is_some());
        assert_eq!(mgr.queued_event_count(), 0);
    }

    #[test]
    fn test_async_event_manager_config() {
        let mgr = AsyncEventManager::new(4);

        // All events enabled by default
        assert_eq!(mgr.get_config(), 0xFFFFFFFF);

        // Disable SMART events (type 1)
        mgr.set_config(0xFFFFFFFD); // Clear bit 1

        // Queue an AER
        mgr.queue_aer(1);

        // SMART event should not satisfy AER
        let result = mgr.post_event(AsyncEvent::smart(AsyncEventSmartInfo::Temperature));
        assert!(result.is_none());

        // Error event should still work
        let result = mgr.post_event(AsyncEvent::error(AsyncEventErrorInfo::DiagnosticFailure));
        assert!(result.is_some());
    }

    #[test]
    fn test_async_event_manager_clear() {
        let mgr = AsyncEventManager::new(4);

        // Add some state
        mgr.queue_aer(1);
        mgr.queue_aer(2);
        let _ = mgr.post_event(AsyncEvent::namespace_changed()); // Satisfies AER 1
        let _ = mgr.post_event(AsyncEvent::namespace_changed()); // Satisfies AER 2
        let _ = mgr.post_event(AsyncEvent::namespace_changed()); // Queued

        assert_eq!(mgr.queued_event_count(), 1);

        // Clear everything
        mgr.clear();
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.queued_event_count(), 0);
    }

    #[test]
    fn test_async_event_types() {
        assert_eq!(AsyncEventType::Error.bits(), 0);
        assert_eq!(AsyncEventType::Smart.bits(), 1);
        assert_eq!(AsyncEventType::Notice.bits(), 2);
        assert_eq!(AsyncEventType::IoCommandSet.bits(), 6);
        assert_eq!(AsyncEventType::VendorSpecific.bits(), 7);
    }
}
