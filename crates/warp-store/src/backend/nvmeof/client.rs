//! NVMe-oF Client
//!
//! Client for connecting to NVMe-oF targets.

use std::sync::Arc;

use bytes::Bytes;
use tracing::{debug, trace};

use super::config::{NvmeOfBackendConfig, TransportPreference};
use super::error::{NvmeOfBackendError, NvmeOfBackendResult};
use super::pool::{NvmeOfConnectionPool, PooledConnection};
use super::transport::{CommandCapsule, NvmeCommand, admin_opcode, io_opcode};

/// NVMe-oF client for initiator operations
pub struct NvmeOfClient {
    /// Configuration
    config: NvmeOfBackendConfig,

    /// Connection pool
    pool: Arc<NvmeOfConnectionPool>,
}

impl NvmeOfClient {
    /// Create a new client
    pub async fn new(config: NvmeOfBackendConfig) -> NvmeOfBackendResult<Self> {
        let pool = Arc::new(NvmeOfConnectionPool::new(
            config.pool.clone(),
            config.transport_preference.clone(),
        ));

        // Add all configured targets to the pool
        for target in &config.targets {
            pool.add_target(target.clone())?;
        }

        debug!(
            "NVMe-oF client created with {} targets",
            config.targets.len()
        );

        Ok(Self { config, pool })
    }

    /// Get connection pool
    pub fn pool(&self) -> &Arc<NvmeOfConnectionPool> {
        &self.pool
    }

    /// Get a connection to a target
    pub async fn get_connection(&self, nqn: &str) -> NvmeOfBackendResult<Arc<PooledConnection>> {
        self.pool.get_connection(nqn).await
    }

    /// Read blocks from a namespace
    pub async fn read(
        &self,
        target_nqn: &str,
        namespace_id: u32,
        start_lba: u64,
        block_count: u32,
    ) -> NvmeOfBackendResult<Bytes> {
        let conn = self.get_connection(target_nqn).await?;
        conn.begin_command();

        // Build NVMe Read command
        let mut cmd = NvmeCommand::new();
        cmd.set_opcode(io_opcode::READ);
        cmd.set_nsid(namespace_id);
        cmd.set_slba(start_lba);
        cmd.set_nlb(block_count as u16 - 1); // NVMe uses 0-based count

        let mut capsule = CommandCapsule::new(cmd);

        // Execute command via transport
        let response = conn.transport.execute(&mut capsule).await?;

        conn.end_command();
        self.pool.return_connection(conn);

        // Check for errors
        if !response.completion.is_success() {
            return Err(NvmeOfBackendError::Io(format!(
                "NVMe Read failed with status {:#x}",
                response.completion.status()
            )));
        }

        // Get data from response
        let data = response.data.unwrap_or_default();

        trace!(
            "Read {} blocks from LBA {} on {}/ns{}",
            block_count, start_lba, target_nqn, namespace_id
        );

        Ok(data)
    }

    /// Write blocks to a namespace
    pub async fn write(
        &self,
        target_nqn: &str,
        namespace_id: u32,
        start_lba: u64,
        data: Bytes,
    ) -> NvmeOfBackendResult<()> {
        let conn = self.get_connection(target_nqn).await?;
        conn.begin_command();

        let block_count =
            (data.len() + self.config.block_size as usize - 1) / self.config.block_size as usize;

        // Build NVMe Write command
        let mut cmd = NvmeCommand::new();
        cmd.set_opcode(io_opcode::WRITE);
        cmd.set_nsid(namespace_id);
        cmd.set_slba(start_lba);
        cmd.set_nlb(block_count as u16 - 1); // NVMe uses 0-based count

        let mut capsule = CommandCapsule::with_data(cmd, data);

        // Execute command via transport
        let response = conn.transport.execute(&mut capsule).await?;

        conn.end_command();
        self.pool.return_connection(conn);

        // Check for errors
        if !response.completion.is_success() {
            return Err(NvmeOfBackendError::Io(format!(
                "NVMe Write failed with status {:#x}",
                response.completion.status()
            )));
        }

        trace!(
            "Wrote {} blocks to LBA {} on {}/ns{}",
            block_count, start_lba, target_nqn, namespace_id
        );

        Ok(())
    }

    /// Flush a namespace
    pub async fn flush(&self, target_nqn: &str, namespace_id: u32) -> NvmeOfBackendResult<()> {
        let conn = self.get_connection(target_nqn).await?;
        conn.begin_command();

        // Build NVMe Flush command
        let mut cmd = NvmeCommand::new();
        cmd.set_opcode(io_opcode::FLUSH);
        cmd.set_nsid(namespace_id);

        let mut capsule = CommandCapsule::new(cmd);

        // Execute command via transport
        let response = conn.transport.execute(&mut capsule).await?;

        conn.end_command();
        self.pool.return_connection(conn);

        if !response.completion.is_success() {
            return Err(NvmeOfBackendError::Io(format!(
                "NVMe Flush failed with status {:#x}",
                response.completion.status()
            )));
        }

        trace!("Flushed {}/ns{}", target_nqn, namespace_id);
        Ok(())
    }

    /// TRIM/Deallocate blocks
    pub async fn trim(
        &self,
        target_nqn: &str,
        namespace_id: u32,
        start_lba: u64,
        block_count: u32,
    ) -> NvmeOfBackendResult<()> {
        let conn = self.get_connection(target_nqn).await?;
        conn.begin_command();

        // Build NVMe Dataset Management (TRIM) command
        let mut cmd = NvmeCommand::new();
        cmd.set_opcode(io_opcode::DATASET_MANAGEMENT);
        cmd.set_nsid(namespace_id);
        cmd.set_slba(start_lba);
        cmd.set_nlb(block_count as u16 - 1);

        let mut capsule = CommandCapsule::new(cmd);

        // Execute command via transport
        let response = conn.transport.execute(&mut capsule).await?;

        conn.end_command();
        self.pool.return_connection(conn);

        if !response.completion.is_success() {
            return Err(NvmeOfBackendError::Io(format!(
                "NVMe TRIM failed with status {:#x}",
                response.completion.status()
            )));
        }

        trace!(
            "Trimmed {} blocks from LBA {} on {}/ns{}",
            block_count, start_lba, target_nqn, namespace_id
        );

        Ok(())
    }

    /// Discover targets from a discovery service
    ///
    /// Connects to the NVMe-oF discovery service at the given address
    /// and retrieves the list of available NVMe subsystems.
    pub async fn discover(&self, address: &str) -> NvmeOfBackendResult<Vec<DiscoveredTarget>> {
        use std::net::ToSocketAddrs;

        debug!("Discovering targets at {}", address);

        // Parse address
        let socket_addr = address
            .to_socket_addrs()
            .map_err(|e| NvmeOfBackendError::Connection(format!("Invalid address: {}", e)))?
            .next()
            .ok_or_else(|| NvmeOfBackendError::Connection("No address resolved".to_string()))?;

        // Create a temporary connection pool for discovery
        let temp_pool = NvmeOfConnectionPool::new(
            self.config.pool.clone(),
            self.config.transport_preference.clone(),
        );

        // Add discovery target
        let discovery_nqn = "nqn.2014-08.org.nvmexpress.discovery";
        temp_pool.add_target(super::config::NvmeOfTargetConfig {
            nqn: discovery_nqn.to_string(),
            addresses: vec![socket_addr],
            ..Default::default()
        })?;

        // Get connection
        let conn = temp_pool.get_connection(discovery_nqn).await?;
        conn.begin_command();

        // Build Get Log Page command for Discovery Log (page 0x70)
        let mut cmd = NvmeCommand::new();
        cmd.set_opcode(admin_opcode::GET_LOG_PAGE);
        cmd.set_nsid(0);
        // CDW10: LID = 0x70 (Discovery), NUMDL = 0xFFF (4KB)
        cmd.cdw10 = 0x70 | (0xFFF << 16);
        // CDW11: NUMDU = 0
        cmd.cdw11 = 0;

        let mut capsule = CommandCapsule::new(cmd);

        // Execute command
        let response = conn.transport.execute(&mut capsule).await?;

        conn.end_command();
        temp_pool.return_connection(conn);

        if !response.completion.is_success() {
            return Err(NvmeOfBackendError::Io(format!(
                "Discovery failed with status {:#x}",
                response.completion.status()
            )));
        }

        // Parse discovery log page
        let data = response.data.unwrap_or_default();
        let targets = parse_discovery_log(&data, socket_addr.port())?;

        debug!("Discovered {} targets at {}", targets.len(), address);
        Ok(targets)
    }

    /// Get namespace information
    ///
    /// Sends an Identify Namespace command to retrieve detailed
    /// information about a specific namespace.
    pub async fn get_namespace_info(
        &self,
        target_nqn: &str,
        namespace_id: u32,
    ) -> NvmeOfBackendResult<NamespaceInfo> {
        let conn = self.get_connection(target_nqn).await?;
        conn.begin_command();

        // Build Identify Namespace command
        let mut cmd = NvmeCommand::new();
        cmd.set_opcode(admin_opcode::IDENTIFY);
        cmd.set_nsid(namespace_id);
        // CDW10: CNS = 0x00 (Identify Namespace)
        cmd.cdw10 = 0x00;

        let mut capsule = CommandCapsule::new(cmd);

        // Execute command
        let response = conn.transport.execute(&mut capsule).await?;

        conn.end_command();
        self.pool.return_connection(conn);

        if !response.completion.is_success() {
            return Err(NvmeOfBackendError::Io(format!(
                "Identify Namespace failed with status {:#x}",
                response.completion.status()
            )));
        }

        // Parse Identify Namespace data structure
        let data = response.data.unwrap_or_default();
        if data.len() < 4096 {
            return Err(NvmeOfBackendError::Protocol(
                "Identify Namespace response too short".to_string(),
            ));
        }

        // Parse key fields from Identify Namespace structure
        // NSZE (Namespace Size): bytes 0-7
        let size_blocks = u64::from_le_bytes(data[0..8].try_into().unwrap());

        // NCAP (Namespace Capacity): bytes 8-15
        let capacity_blocks = u64::from_le_bytes(data[8..16].try_into().unwrap());

        // NUSE (Namespace Utilization): bytes 16-23
        let utilization_blocks = u64::from_le_bytes(data[16..24].try_into().unwrap());

        // FLBAS (Formatted LBA Size): byte 26
        let flbas = data[26];
        let lba_format_index = flbas & 0x0F;

        // LBA Format structures start at byte 128, each is 4 bytes
        // LBAF[n] at offset 128 + 4*n: MS (bits 0-15), LBADS (bits 16-23), RP (bits 24-25)
        let lbaf_offset = 128 + (lba_format_index as usize) * 4;
        if lbaf_offset + 4 > data.len() {
            return Err(NvmeOfBackendError::Protocol(
                "Invalid LBA format index".to_string(),
            ));
        }

        let lbaf = u32::from_le_bytes(data[lbaf_offset..lbaf_offset + 4].try_into().unwrap());
        let lba_data_size = (lbaf >> 16) & 0xFF; // LBADS field (power of 2)
        let block_size = 1u32 << lba_data_size;

        trace!(
            "Namespace {} info: size={} blocks, block_size={}, capacity={}, utilization={}",
            namespace_id, size_blocks, block_size, capacity_blocks, utilization_blocks
        );

        Ok(NamespaceInfo {
            namespace_id,
            size_blocks,
            block_size,
            capacity_blocks,
            utilization_blocks,
        })
    }

    /// Get target list
    pub fn targets(&self) -> Vec<String> {
        self.config.targets.iter().map(|t| t.nqn.clone()).collect()
    }
}

/// Discovered NVMe-oF target
#[derive(Debug, Clone)]
pub struct DiscoveredTarget {
    /// Target NQN
    pub nqn: String,

    /// Transport type
    pub transport: TransportPreference,

    /// Address
    pub address: String,

    /// Port
    pub port: u16,

    /// Subsystem type (discovery or NVM)
    pub subsystem_type: u8,
}

/// Parse discovery log page into discovered targets
fn parse_discovery_log(
    data: &Bytes,
    default_port: u16,
) -> NvmeOfBackendResult<Vec<DiscoveredTarget>> {
    if data.len() < 16 {
        return Ok(Vec::new());
    }

    // Discovery Log Header:
    // bytes 0-7: Generation Counter
    // bytes 8-15: Number of Records
    // bytes 16-23: Record Format
    let num_records = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;

    if num_records == 0 {
        return Ok(Vec::new());
    }

    let mut targets = Vec::with_capacity(num_records);
    let mut offset = 1024; // Discovery Log Entries start at offset 1024

    for _ in 0..num_records {
        if offset + 1024 > data.len() {
            break;
        }

        let entry = &data[offset..offset + 1024];

        // Discovery Log Entry (1024 bytes per entry):
        // byte 0: Transport Type (0x01 = RDMA, 0x03 = TCP)
        // byte 1: Address Family (0x01 = IPv4, 0x02 = IPv6)
        // byte 2: Subsystem Type (0x01 = Discovery, 0x02 = NVM)
        // bytes 3: TREQ (Transport Requirements)
        // bytes 4-5: Port ID
        // bytes 6-7: Controller ID
        // bytes 8-9: Admin Max SQ Size
        // bytes 32-63: Transport Address (TRADDR)
        // bytes 64-287: Transport Service ID (TRSVCID)
        // bytes 288-543: Subsystem NQN
        let transport_type = entry[0];
        let subsystem_type = entry[2];

        // Parse transport address (null-terminated string)
        let traddr_end = entry[32..64].iter().position(|&b| b == 0).unwrap_or(32);
        let traddr = String::from_utf8_lossy(&entry[32..32 + traddr_end]).to_string();

        // Parse transport service ID (port, null-terminated string)
        let trsvcid_end = entry[64..96].iter().position(|&b| b == 0).unwrap_or(32);
        let trsvcid = String::from_utf8_lossy(&entry[64..64 + trsvcid_end]).to_string();
        let port = trsvcid.parse().unwrap_or(default_port);

        // Parse NQN (null-terminated string)
        let nqn_end = entry[288..544].iter().position(|&b| b == 0).unwrap_or(256);
        let nqn = String::from_utf8_lossy(&entry[288..288 + nqn_end]).to_string();

        let transport = match transport_type {
            0x01 => TransportPreference::Rdma,
            0x03 => TransportPreference::Tcp,
            _ => TransportPreference::Tcp,
        };

        targets.push(DiscoveredTarget {
            nqn,
            transport,
            address: traddr,
            port,
            subsystem_type,
        });

        offset += 1024;
    }

    Ok(targets)
}

/// Namespace information
#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    /// Namespace ID
    pub namespace_id: u32,

    /// Size in blocks
    pub size_blocks: u64,

    /// Block size
    pub block_size: u32,

    /// Capacity in blocks
    pub capacity_blocks: u64,

    /// Current utilization in blocks
    pub utilization_blocks: u64,
}

impl NamespaceInfo {
    /// Get size in bytes
    pub fn size_bytes(&self) -> u64 {
        self.size_blocks * self.block_size as u64
    }

    /// Get utilization percentage
    pub fn utilization_percent(&self) -> f64 {
        if self.capacity_blocks == 0 {
            return 0.0;
        }
        (self.utilization_blocks as f64 / self.capacity_blocks as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::NvmeOfTargetConfig;
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let config = NvmeOfBackendConfig {
            targets: vec![NvmeOfTargetConfig {
                nqn: "nqn.2024-01.io.warp:test".to_string(),
                addresses: vec!["127.0.0.1:4420".parse().unwrap()],
                ..Default::default()
            }],
            ..Default::default()
        };

        let client = NvmeOfClient::new(config).await.unwrap();
        assert_eq!(client.targets().len(), 1);
    }
}
