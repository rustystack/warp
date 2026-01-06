//! NVMe-oF Connection Management
//!
//! This module handles NVMe-oF connections, including the connection
//! lifecycle, command processing, and state management.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
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
            Some(AdminOpcode::AsyncEventRequest) => {
                // TODO: Implement async events
                Ok(ResponseCapsule::success(cid, 0, sq_head))
            }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Full tests require mock transport and namespace handler
    // These are placeholder tests for the basic structures

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.commands_received, 0);
        assert_eq!(stats.bytes_read, 0);
    }
}
