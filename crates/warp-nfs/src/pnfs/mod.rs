//! Parallel NFS (pNFS) implementation
//!
//! pNFS allows clients to access storage devices directly, bypassing
//! the NFS server for data operations while maintaining metadata
//! through the server.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;

use crate::error::NfsStatus;
use crate::nfs4::StateId;
use crate::rpc::xdr::{XdrDecoder, XdrEncoder};

/// Layout type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LayoutType {
    /// NFSv4.1 file layout (RFC 5661)
    NfsV41Files = 1,
    /// Object-based storage (RFC 5664)
    Osd2Objects = 2,
    /// Block/volume layout (RFC 5663)
    BlockVolume = 3,
    /// Flex files (RFC 8435)
    FlexFiles = 4,
}

impl TryFrom<u32> for LayoutType {
    type Error = NfsStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NfsV41Files),
            2 => Ok(Self::Osd2Objects),
            3 => Ok(Self::BlockVolume),
            4 => Ok(Self::FlexFiles),
            _ => Err(NfsStatus::LayoutUnavailable),
        }
    }
}

/// Layout I/O mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LayoutIoMode {
    /// Read-only access
    Read = 1,
    /// Read-write access
    ReadWrite = 2,
    /// Any mode
    Any = 3,
}

impl TryFrom<u32> for LayoutIoMode {
    type Error = NfsStatus;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Read),
            2 => Ok(Self::ReadWrite),
            3 => Ok(Self::Any),
            _ => Err(NfsStatus::Inval),
        }
    }
}

/// Layout segment
#[derive(Debug, Clone)]
pub struct LayoutSegment {
    /// Offset
    pub offset: u64,
    /// Length (0 = EOF)
    pub length: u64,
    /// I/O mode
    pub iomode: LayoutIoMode,
    /// Layout type
    pub layout_type: LayoutType,
    /// Layout content (type-specific)
    pub layout_content: LayoutContent,
}

/// Layout content (type-specific data)
#[derive(Debug, Clone)]
pub enum LayoutContent {
    /// NFSv4.1 file layout
    NfsV41Files(FileLayout),
    /// Flex files layout
    FlexFiles(FlexFilesLayout),
}

/// NFSv4.1 file layout (RFC 5661 Section 13)
#[derive(Debug, Clone)]
pub struct FileLayout {
    /// Device ID
    pub device_id: DeviceId,
    /// NFSv4.1 file layout-specific info
    pub nfl_util: u32,
    /// First stripe index
    pub first_stripe_index: u32,
    /// Pattern offset
    pub pattern_offset: u64,
    /// Filehandle list
    pub filehandles: Vec<Bytes>,
}

/// Flex files layout (RFC 8435)
#[derive(Debug, Clone)]
pub struct FlexFilesLayout {
    /// Stripe unit
    pub stripe_unit: u64,
    /// Mirrors
    pub mirrors: Vec<FlexFilesMirror>,
    /// Flags
    pub flags: u32,
    /// Stats collect hint
    pub stats_collect_hint: u32,
}

/// Flex files mirror
#[derive(Debug, Clone)]
pub struct FlexFilesMirror {
    /// Data servers
    pub data_servers: Vec<FlexFilesDataServer>,
    /// Efficiency
    pub efficiency: u32,
}

/// Flex files data server
#[derive(Debug, Clone)]
pub struct FlexFilesDataServer {
    /// Device ID
    pub device_id: DeviceId,
    /// Filehandle
    pub filehandle: Bytes,
    /// User principal
    pub user: Option<String>,
    /// Group principal
    pub group: Option<String>,
}

/// Device ID (16 bytes)
pub type DeviceId = [u8; 16];

/// Device address for data servers
#[derive(Debug, Clone)]
pub struct DeviceAddress {
    /// Layout type this applies to
    pub layout_type: LayoutType,
    /// Device-specific address
    pub address: DeviceAddressContent,
}

/// Device address content (type-specific)
#[derive(Debug, Clone)]
pub enum DeviceAddressContent {
    /// NFSv4.1 multipath data server list
    NfsV41Files(MultiPathList),
    /// Flex files: list of addresses
    FlexFiles(Vec<SocketAddr>),
}

/// Multipath list for NFSv4.1 file layout
#[derive(Debug, Clone)]
pub struct MultiPathList {
    /// List of data server addresses
    pub data_servers: Vec<Vec<NetAddr>>,
}

/// Network address
#[derive(Debug, Clone)]
pub struct NetAddr {
    /// Network ID (e.g., "tcp", "tcp6")
    pub netid: String,
    /// Universal address (e.g., "192.168.1.1.8.1" for port 2049)
    pub addr: String,
}

impl NetAddr {
    /// Create a new network address
    pub fn new(netid: impl Into<String>, addr: impl Into<String>) -> Self {
        Self {
            netid: netid.into(),
            addr: addr.into(),
        }
    }

    /// Create from socket address
    pub fn from_socket_addr(addr: &SocketAddr) -> Self {
        let (netid, universal) = match addr {
            SocketAddr::V4(v4) => {
                let ip = v4.ip();
                let port = v4.port();
                let port_hi = (port >> 8) as u8;
                let port_lo = (port & 0xff) as u8;
                (
                    "tcp".to_string(),
                    format!(
                        "{}.{}.{}.{}.{}.{}",
                        ip.octets()[0],
                        ip.octets()[1],
                        ip.octets()[2],
                        ip.octets()[3],
                        port_hi,
                        port_lo
                    ),
                )
            }
            SocketAddr::V6(v6) => {
                let port = v6.port();
                ("tcp6".to_string(), format!("{}.{}.{}", v6.ip(), port >> 8, port & 0xff))
            }
        };
        Self {
            netid,
            addr: universal,
        }
    }
}

/// LAYOUTGET arguments
#[derive(Debug, Clone)]
pub struct LayoutGetArgs {
    /// Signal layout available
    pub signal_layout_avail: bool,
    /// Layout type
    pub layout_type: LayoutType,
    /// I/O mode
    pub iomode: LayoutIoMode,
    /// Offset
    pub offset: u64,
    /// Length
    pub length: u64,
    /// Minimum length
    pub minlength: u64,
    /// Stateid
    pub stateid: StateId,
    /// Max count
    pub maxcount: u32,
}

impl LayoutGetArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let signal_layout_avail = dec.decode_bool()?;
        let layout_type_val = dec.decode_u32()?;
        let layout_type = LayoutType::try_from(layout_type_val)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid layout type"))?;
        let iomode_val = dec.decode_u32()?;
        let iomode = LayoutIoMode::try_from(iomode_val)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid iomode"))?;
        let offset = dec.decode_u64()?;
        let length = dec.decode_u64()?;
        let minlength = dec.decode_u64()?;
        let stateid = StateId::decode(dec)?;
        let maxcount = dec.decode_u32()?;

        Ok(Self {
            signal_layout_avail,
            layout_type,
            iomode,
            offset,
            length,
            minlength,
            stateid,
            maxcount,
        })
    }
}

/// LAYOUTGET result
#[derive(Debug, Clone)]
pub struct LayoutGetRes {
    /// Return on close
    pub return_on_close: bool,
    /// Layout stateid
    pub stateid: StateId,
    /// Layout segments
    pub segments: Vec<LayoutSegment>,
}

/// LAYOUTCOMMIT arguments
#[derive(Debug, Clone)]
pub struct LayoutCommitArgs {
    /// Offset
    pub offset: u64,
    /// Length
    pub length: u64,
    /// Reclaim
    pub reclaim: bool,
    /// Stateid
    pub stateid: StateId,
    /// Last write offset
    pub last_write_offset: Option<u64>,
    /// Time modify
    pub time_modify: Option<(u64, u32)>,
    /// Layout type-specific data
    pub layout_data: Bytes,
}

/// LAYOUTRETURN arguments
#[derive(Debug, Clone)]
pub struct LayoutReturnArgs {
    /// Reclaim
    pub reclaim: bool,
    /// Layout type
    pub layout_type: LayoutType,
    /// I/O mode
    pub iomode: LayoutIoMode,
    /// Return type (file, fsid, all)
    pub return_type: LayoutReturnType,
}

/// Layout return type
#[derive(Debug, Clone)]
pub enum LayoutReturnType {
    /// Return layout for a file
    File {
        offset: u64,
        length: u64,
        stateid: StateId,
        data: Bytes,
    },
    /// Return layout for fsid
    Fsid,
    /// Return all layouts
    All,
}

/// GETDEVICEINFO arguments
#[derive(Debug, Clone)]
pub struct GetDeviceInfoArgs {
    /// Device ID
    pub device_id: DeviceId,
    /// Layout type
    pub layout_type: LayoutType,
    /// Max count
    pub maxcount: u32,
    /// Notify types bitmap
    pub notify_types: u32,
}

impl GetDeviceInfoArgs {
    /// Decode from XDR
    pub fn decode(dec: &mut XdrDecoder) -> std::io::Result<Self> {
        let device_id_vec = dec.decode_opaque_fixed(16)?;
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&device_id_vec);
        let layout_type_val = dec.decode_u32()?;
        let layout_type = LayoutType::try_from(layout_type_val)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid layout type"))?;
        let maxcount = dec.decode_u32()?;
        let notify_types = dec.decode_u32()?;

        Ok(Self {
            device_id,
            layout_type,
            maxcount,
            notify_types,
        })
    }
}

/// pNFS layout manager
#[derive(Debug)]
pub struct LayoutManager {
    /// Layouts by (client_id, filehandle_hash)
    layouts: DashMap<(u64, u64), LayoutEntry>,
    /// Devices by ID
    devices: DashMap<DeviceId, DeviceEntry>,
    /// Next device ID counter
    device_counter: AtomicU64,
    /// Layout stateid counter
    layout_stateid_counter: AtomicU64,
}

/// Layout entry in the manager
#[derive(Debug, Clone)]
struct LayoutEntry {
    /// Layout stateid
    stateid: StateId,
    /// Segments
    segments: Vec<LayoutSegment>,
    /// Return on close
    return_on_close: bool,
    /// Created time
    created: Instant,
}

/// Device entry in the manager
#[derive(Debug, Clone)]
struct DeviceEntry {
    /// Device ID
    device_id: DeviceId,
    /// Device address
    address: DeviceAddress,
    /// Created time
    created: Instant,
}

impl LayoutManager {
    /// Create a new layout manager
    pub fn new() -> Self {
        Self {
            layouts: DashMap::new(),
            devices: DashMap::new(),
            device_counter: AtomicU64::new(1),
            layout_stateid_counter: AtomicU64::new(1),
        }
    }

    /// Generate a new device ID
    pub fn generate_device_id(&self) -> DeviceId {
        let counter = self.device_counter.fetch_add(1, Ordering::SeqCst);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&counter.to_be_bytes());
        id
    }

    /// Generate a layout stateid
    pub fn generate_layout_stateid(&self) -> StateId {
        let counter = self.layout_stateid_counter.fetch_add(1, Ordering::SeqCst);
        let mut other = [0u8; 12];
        other[..8].copy_from_slice(&counter.to_be_bytes());
        other[8..12].copy_from_slice(b"LYOT");
        StateId::new(1, other)
    }

    /// Register a device
    pub fn register_device(&self, address: DeviceAddress) -> DeviceId {
        let device_id = self.generate_device_id();
        let entry = DeviceEntry {
            device_id,
            address,
            created: Instant::now(),
        };
        self.devices.insert(device_id, entry);
        device_id
    }

    /// Get device address
    pub fn get_device(&self, device_id: &DeviceId) -> Option<DeviceAddress> {
        self.devices.get(device_id).map(|e| e.address.clone())
    }

    /// Grant a layout
    pub fn grant_layout(
        &self,
        client_id: u64,
        fh_hash: u64,
        segments: Vec<LayoutSegment>,
        return_on_close: bool,
    ) -> StateId {
        let stateid = self.generate_layout_stateid();
        let entry = LayoutEntry {
            stateid,
            segments,
            return_on_close,
            created: Instant::now(),
        };
        self.layouts.insert((client_id, fh_hash), entry);
        stateid
    }

    /// Get layout for a file
    pub fn get_layout(&self, client_id: u64, fh_hash: u64) -> Option<(StateId, Vec<LayoutSegment>)> {
        self.layouts
            .get(&(client_id, fh_hash))
            .map(|e| (e.stateid, e.segments.clone()))
    }

    /// Return (release) a layout
    pub fn return_layout(&self, client_id: u64, fh_hash: u64) -> Option<StateId> {
        self.layouts
            .remove(&(client_id, fh_hash))
            .map(|(_, e)| e.stateid)
    }

    /// Return all layouts for a client
    pub fn return_all_client_layouts(&self, client_id: u64) {
        self.layouts.retain(|(c, _), _| *c != client_id);
    }
}

impl Default for LayoutManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_type() {
        assert_eq!(LayoutType::try_from(1).unwrap(), LayoutType::NfsV41Files);
        assert_eq!(LayoutType::try_from(4).unwrap(), LayoutType::FlexFiles);
        assert!(LayoutType::try_from(99).is_err());
    }

    #[test]
    fn test_layout_io_mode() {
        assert_eq!(LayoutIoMode::try_from(1).unwrap(), LayoutIoMode::Read);
        assert_eq!(LayoutIoMode::try_from(2).unwrap(), LayoutIoMode::ReadWrite);
        assert!(LayoutIoMode::try_from(99).is_err());
    }

    #[test]
    fn test_net_addr_from_socket() {
        let addr: SocketAddr = "192.168.1.1:2049".parse().unwrap();
        let net_addr = NetAddr::from_socket_addr(&addr);
        assert_eq!(net_addr.netid, "tcp");
        assert_eq!(net_addr.addr, "192.168.1.1.8.1"); // 2049 = 8*256 + 1
    }

    #[test]
    fn test_layout_manager_device() {
        let mgr = LayoutManager::new();
        let addr = DeviceAddress {
            layout_type: LayoutType::NfsV41Files,
            address: DeviceAddressContent::NfsV41Files(MultiPathList {
                data_servers: vec![],
            }),
        };
        let device_id = mgr.register_device(addr.clone());
        let retrieved = mgr.get_device(&device_id).unwrap();
        assert_eq!(retrieved.layout_type, LayoutType::NfsV41Files);
    }

    #[test]
    fn test_layout_manager_layout() {
        let mgr = LayoutManager::new();
        let segment = LayoutSegment {
            offset: 0,
            length: 1024,
            iomode: LayoutIoMode::Read,
            layout_type: LayoutType::NfsV41Files,
            layout_content: LayoutContent::NfsV41Files(FileLayout {
                device_id: [0; 16],
                nfl_util: 0,
                first_stripe_index: 0,
                pattern_offset: 0,
                filehandles: vec![],
            }),
        };

        let stateid = mgr.grant_layout(1, 12345, vec![segment], false);
        let (retrieved_id, segments) = mgr.get_layout(1, 12345).unwrap();
        assert_eq!(retrieved_id, stateid);
        assert_eq!(segments.len(), 1);

        let returned = mgr.return_layout(1, 12345).unwrap();
        assert_eq!(returned, stateid);
        assert!(mgr.get_layout(1, 12345).is_none());
    }
}
