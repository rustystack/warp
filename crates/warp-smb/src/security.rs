//! Windows security descriptor support
//!
//! Implements Windows security descriptors and ACLs for SMB.

use bytes::{BufMut, BytesMut};

/// Security descriptor control flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityDescriptorControl(u16);

impl SecurityDescriptorControl {
    /// Owner defaulted
    pub const OWNER_DEFAULTED: u16 = 0x0001;
    /// Group defaulted
    pub const GROUP_DEFAULTED: u16 = 0x0002;
    /// DACL present
    pub const DACL_PRESENT: u16 = 0x0004;
    /// DACL defaulted
    pub const DACL_DEFAULTED: u16 = 0x0008;
    /// SACL present
    pub const SACL_PRESENT: u16 = 0x0010;
    /// SACL defaulted
    pub const SACL_DEFAULTED: u16 = 0x0020;
    /// DACL auto inherit required
    pub const DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
    /// SACL auto inherit required
    pub const SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
    /// DACL auto inherited
    pub const DACL_AUTO_INHERITED: u16 = 0x0400;
    /// SACL auto inherited
    pub const SACL_AUTO_INHERITED: u16 = 0x0800;
    /// DACL protected
    pub const DACL_PROTECTED: u16 = 0x1000;
    /// SACL protected
    pub const SACL_PROTECTED: u16 = 0x2000;
    /// RM control valid
    pub const RM_CONTROL_VALID: u16 = 0x4000;
    /// Self relative
    pub const SELF_RELATIVE: u16 = 0x8000;

    /// Create new control flags
    pub fn new(flags: u16) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u16 {
        self.0
    }

    /// Check if flag is set
    pub fn has(&self, flag: u16) -> bool {
        self.0 & flag != 0
    }
}

impl Default for SecurityDescriptorControl {
    fn default() -> Self {
        Self(Self::SELF_RELATIVE)
    }
}

/// Security Identifier (SID)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    /// Revision (always 1)
    pub revision: u8,
    /// Sub-authority count
    pub sub_auth_count: u8,
    /// Identifier authority (6 bytes)
    pub authority: [u8; 6],
    /// Sub-authorities
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Well-known SID: Everyone (S-1-1-0)
    pub fn everyone() -> Self {
        Self {
            revision: 1,
            sub_auth_count: 1,
            authority: [0, 0, 0, 0, 0, 1],
            sub_authorities: vec![0],
        }
    }

    /// Well-known SID: SYSTEM (S-1-5-18)
    pub fn system() -> Self {
        Self {
            revision: 1,
            sub_auth_count: 1,
            authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![18],
        }
    }

    /// Well-known SID: Administrators (S-1-5-32-544)
    pub fn administrators() -> Self {
        Self {
            revision: 1,
            sub_auth_count: 2,
            authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![32, 544],
        }
    }

    /// Well-known SID: Users (S-1-5-32-545)
    pub fn users() -> Self {
        Self {
            revision: 1,
            sub_auth_count: 2,
            authority: [0, 0, 0, 0, 0, 5],
            sub_authorities: vec![32, 545],
        }
    }

    /// Create a SID from a Unix UID
    pub fn from_uid(uid: u32) -> Self {
        // Use WARP domain SID: S-1-22-1-<uid>
        Self {
            revision: 1,
            sub_auth_count: 2,
            authority: [0, 0, 0, 0, 0, 22],
            sub_authorities: vec![1, uid],
        }
    }

    /// Create a SID from a Unix GID
    pub fn from_gid(gid: u32) -> Self {
        // Use WARP domain SID: S-1-22-2-<gid>
        Self {
            revision: 1,
            sub_auth_count: 2,
            authority: [0, 0, 0, 0, 0, 22],
            sub_authorities: vec![2, gid],
        }
    }

    /// Extract Unix UID from SID (if applicable)
    pub fn to_uid(&self) -> Option<u32> {
        if self.authority == [0, 0, 0, 0, 0, 22]
            && self.sub_authorities.len() >= 2
            && self.sub_authorities[0] == 1
        {
            Some(self.sub_authorities[1])
        } else {
            None
        }
    }

    /// Extract Unix GID from SID (if applicable)
    pub fn to_gid(&self) -> Option<u32> {
        if self.authority == [0, 0, 0, 0, 0, 22]
            && self.sub_authorities.len() >= 2
            && self.sub_authorities[0] == 2
        {
            Some(self.sub_authorities[1])
        } else {
            None
        }
    }

    /// Calculate size in bytes
    pub fn size(&self) -> usize {
        8 + (self.sub_authorities.len() * 4)
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 8 {
            return None;
        }

        let revision = data[0];
        let sub_auth_count = data[1];
        let mut authority = [0u8; 6];
        authority.copy_from_slice(&data[2..8]);

        let expected_size = 8 + (sub_auth_count as usize * 4);
        if data.len() < expected_size {
            return None;
        }

        let mut sub_authorities = Vec::with_capacity(sub_auth_count as usize);
        for i in 0..sub_auth_count as usize {
            let offset = 8 + (i * 4);
            let sub_auth = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            sub_authorities.push(sub_auth);
        }

        Some((
            Self {
                revision,
                sub_auth_count,
                authority,
                sub_authorities,
            },
            expected_size,
        ))
    }

    /// Encode to bytes
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.revision);
        buf.put_u8(self.sub_authorities.len() as u8);
        buf.put_slice(&self.authority);
        for sub_auth in &self.sub_authorities {
            buf.put_u32_le(*sub_auth);
        }
    }

    /// Convert to string representation (S-1-...)
    pub fn to_string(&self) -> String {
        let auth_value = u64::from_be_bytes([
            0,
            0,
            self.authority[0],
            self.authority[1],
            self.authority[2],
            self.authority[3],
            self.authority[4],
            self.authority[5],
        ]);

        let mut result = format!("S-{}-{}", self.revision, auth_value);
        for sub_auth in &self.sub_authorities {
            result.push_str(&format!("-{}", sub_auth));
        }
        result
    }
}

/// ACE (Access Control Entry) type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AceType {
    /// Access allowed
    AccessAllowed = 0x00,
    /// Access denied
    AccessDenied = 0x01,
    /// System audit
    SystemAudit = 0x02,
    /// System alarm
    SystemAlarm = 0x03,
    /// Access allowed (compound)
    AccessAllowedCompound = 0x04,
    /// Access allowed (object)
    AccessAllowedObject = 0x05,
    /// Access denied (object)
    AccessDeniedObject = 0x06,
    /// System audit (object)
    SystemAuditObject = 0x07,
    /// System alarm (object)
    SystemAlarmObject = 0x08,
    /// Access allowed (callback)
    AccessAllowedCallback = 0x09,
    /// Access denied (callback)
    AccessDeniedCallback = 0x0A,
    /// Access allowed (callback object)
    AccessAllowedCallbackObject = 0x0B,
    /// Access denied (callback object)
    AccessDeniedCallbackObject = 0x0C,
    /// System audit (callback)
    SystemAuditCallback = 0x0D,
    /// System alarm (callback)
    SystemAlarmCallback = 0x0E,
    /// System audit (callback object)
    SystemAuditCallbackObject = 0x0F,
    /// System alarm (callback object)
    SystemAlarmCallbackObject = 0x10,
}

impl TryFrom<u8> for AceType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::AccessAllowed),
            0x01 => Ok(Self::AccessDenied),
            0x02 => Ok(Self::SystemAudit),
            0x03 => Ok(Self::SystemAlarm),
            0x04 => Ok(Self::AccessAllowedCompound),
            0x05 => Ok(Self::AccessAllowedObject),
            0x06 => Ok(Self::AccessDeniedObject),
            0x07 => Ok(Self::SystemAuditObject),
            0x08 => Ok(Self::SystemAlarmObject),
            0x09 => Ok(Self::AccessAllowedCallback),
            0x0A => Ok(Self::AccessDeniedCallback),
            0x0B => Ok(Self::AccessAllowedCallbackObject),
            0x0C => Ok(Self::AccessDeniedCallbackObject),
            0x0D => Ok(Self::SystemAuditCallback),
            0x0E => Ok(Self::SystemAlarmCallback),
            0x0F => Ok(Self::SystemAuditCallbackObject),
            0x10 => Ok(Self::SystemAlarmCallbackObject),
            _ => Err(()),
        }
    }
}

/// ACE flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AceFlags(u8);

impl AceFlags {
    /// Object inherit
    pub const OBJECT_INHERIT: u8 = 0x01;
    /// Container inherit
    pub const CONTAINER_INHERIT: u8 = 0x02;
    /// No propagate inherit
    pub const NO_PROPAGATE_INHERIT: u8 = 0x04;
    /// Inherit only
    pub const INHERIT_ONLY: u8 = 0x08;
    /// Inherited ACE
    pub const INHERITED_ACE: u8 = 0x10;
    /// Successful access audit
    pub const SUCCESSFUL_ACCESS: u8 = 0x40;
    /// Failed access audit
    pub const FAILED_ACCESS: u8 = 0x80;

    /// Create new flags
    pub fn new(flags: u8) -> Self {
        Self(flags)
    }

    /// Get raw value
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// No flags
    pub fn empty() -> Self {
        Self(0)
    }

    /// Inherit to children
    pub fn inheritable() -> Self {
        Self(Self::OBJECT_INHERIT | Self::CONTAINER_INHERIT)
    }
}

impl Default for AceFlags {
    fn default() -> Self {
        Self::empty()
    }
}

/// Access mask
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessMask(u32);

impl AccessMask {
    // Generic rights
    /// Generic all
    pub const GENERIC_ALL: u32 = 0x10000000;
    /// Generic execute
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    /// Generic write
    pub const GENERIC_WRITE: u32 = 0x40000000;
    /// Generic read
    pub const GENERIC_READ: u32 = 0x80000000;

    // Standard rights
    /// Delete
    pub const DELETE: u32 = 0x00010000;
    /// Read control
    pub const READ_CONTROL: u32 = 0x00020000;
    /// Write DAC
    pub const WRITE_DAC: u32 = 0x00040000;
    /// Write owner
    pub const WRITE_OWNER: u32 = 0x00080000;
    /// Synchronize
    pub const SYNCHRONIZE: u32 = 0x00100000;

    // File-specific rights
    /// Read data / List directory
    pub const FILE_READ_DATA: u32 = 0x00000001;
    /// Write data / Add file
    pub const FILE_WRITE_DATA: u32 = 0x00000002;
    /// Append data / Add subdirectory
    pub const FILE_APPEND_DATA: u32 = 0x00000004;
    /// Read extended attributes
    pub const FILE_READ_EA: u32 = 0x00000008;
    /// Write extended attributes
    pub const FILE_WRITE_EA: u32 = 0x00000010;
    /// Execute / Traverse
    pub const FILE_EXECUTE: u32 = 0x00000020;
    /// Delete child
    pub const FILE_DELETE_CHILD: u32 = 0x00000040;
    /// Read attributes
    pub const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
    /// Write attributes
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x00000100;

    // Combined
    /// Full control
    pub const FILE_ALL_ACCESS: u32 = 0x001F01FF;
    /// Read
    pub const FILE_GENERIC_READ: u32 = Self::FILE_READ_DATA
        | Self::FILE_READ_EA
        | Self::FILE_READ_ATTRIBUTES
        | Self::READ_CONTROL
        | Self::SYNCHRONIZE;
    /// Write
    pub const FILE_GENERIC_WRITE: u32 = Self::FILE_WRITE_DATA
        | Self::FILE_WRITE_EA
        | Self::FILE_WRITE_ATTRIBUTES
        | Self::FILE_APPEND_DATA
        | Self::READ_CONTROL
        | Self::SYNCHRONIZE;
    /// Execute
    pub const FILE_GENERIC_EXECUTE: u32 =
        Self::FILE_EXECUTE | Self::FILE_READ_ATTRIBUTES | Self::READ_CONTROL | Self::SYNCHRONIZE;

    /// Create new mask
    pub fn new(mask: u32) -> Self {
        Self(mask)
    }

    /// Get raw value
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Check if mask contains rights
    pub fn contains(&self, rights: u32) -> bool {
        self.0 & rights == rights
    }

    /// Full control
    pub fn full_control() -> Self {
        Self(Self::FILE_ALL_ACCESS)
    }

    /// Read only
    pub fn read_only() -> Self {
        Self(Self::FILE_GENERIC_READ)
    }

    /// Read/Write
    pub fn read_write() -> Self {
        Self(Self::FILE_GENERIC_READ | Self::FILE_GENERIC_WRITE)
    }
}

/// ACE (Access Control Entry)
#[derive(Debug, Clone)]
pub struct Ace {
    /// ACE type
    pub ace_type: AceType,
    /// ACE flags
    pub flags: AceFlags,
    /// Access mask
    pub mask: AccessMask,
    /// SID
    pub sid: Sid,
}

impl Ace {
    /// Create an allow ACE
    pub fn allow(sid: Sid, mask: AccessMask) -> Self {
        Self {
            ace_type: AceType::AccessAllowed,
            flags: AceFlags::empty(),
            mask,
            sid,
        }
    }

    /// Create a deny ACE
    pub fn deny(sid: Sid, mask: AccessMask) -> Self {
        Self {
            ace_type: AceType::AccessDenied,
            flags: AceFlags::empty(),
            mask,
            sid,
        }
    }

    /// Set as inheritable
    pub fn inheritable(mut self) -> Self {
        self.flags = AceFlags::inheritable();
        self
    }

    /// Calculate size
    pub fn size(&self) -> usize {
        4 + self.sid.size() // header + SID
    }
}

/// ACL (Access Control List)
#[derive(Debug, Clone)]
pub struct Acl {
    /// Revision
    pub revision: u8,
    /// ACEs
    pub aces: Vec<Ace>,
}

impl Acl {
    /// Create a new ACL
    pub fn new() -> Self {
        Self {
            revision: 2,
            aces: Vec::new(),
        }
    }

    /// Add an ACE
    pub fn add_ace(&mut self, ace: Ace) {
        self.aces.push(ace);
    }

    /// Calculate size
    pub fn size(&self) -> usize {
        8 + self.aces.iter().map(|a| a.size()).sum::<usize>()
    }
}

impl Default for Acl {
    fn default() -> Self {
        Self::new()
    }
}

/// Security descriptor
#[derive(Debug, Clone)]
pub struct SecurityDescriptor {
    /// Revision
    pub revision: u8,
    /// Control flags
    pub control: SecurityDescriptorControl,
    /// Owner SID
    pub owner: Option<Sid>,
    /// Group SID
    pub group: Option<Sid>,
    /// SACL (System ACL)
    pub sacl: Option<Acl>,
    /// DACL (Discretionary ACL)
    pub dacl: Option<Acl>,
}

impl SecurityDescriptor {
    /// Create a new empty security descriptor
    pub fn new() -> Self {
        Self {
            revision: 1,
            control: SecurityDescriptorControl::default(),
            owner: None,
            group: None,
            sacl: None,
            dacl: None,
        }
    }

    /// Create from POSIX mode
    pub fn from_posix(uid: u32, gid: u32, mode: u32) -> Self {
        let owner = Sid::from_uid(uid);
        let group = Sid::from_gid(gid);

        let mut dacl = Acl::new();

        // Owner permissions
        let owner_mask = mode_to_mask((mode >> 6) & 0o7);
        dacl.add_ace(Ace::allow(owner.clone(), owner_mask).inheritable());

        // Group permissions
        let group_mask = mode_to_mask((mode >> 3) & 0o7);
        dacl.add_ace(Ace::allow(group.clone(), group_mask).inheritable());

        // Other permissions
        let other_mask = mode_to_mask(mode & 0o7);
        dacl.add_ace(Ace::allow(Sid::everyone(), other_mask).inheritable());

        Self {
            revision: 1,
            control: SecurityDescriptorControl::new(
                SecurityDescriptorControl::SELF_RELATIVE | SecurityDescriptorControl::DACL_PRESENT,
            ),
            owner: Some(owner),
            group: Some(group),
            sacl: None,
            dacl: Some(dacl),
        }
    }

    /// Convert to POSIX mode
    pub fn to_posix_mode(&self) -> u32 {
        let dacl = match &self.dacl {
            Some(dacl) => dacl,
            None => return 0o755, // Default
        };

        let mut mode = 0u32;

        for ace in &dacl.aces {
            if ace.ace_type != AceType::AccessAllowed {
                continue;
            }

            let bits = mask_to_mode(ace.mask);

            if ace.sid.to_uid().is_some() {
                mode |= bits << 6;
            } else if ace.sid.to_gid().is_some() {
                mode |= bits << 3;
            } else if ace.sid == Sid::everyone() {
                mode |= bits;
            }
        }

        mode
    }
}

impl Default for SecurityDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert POSIX mode bits (0-7) to access mask
fn mode_to_mask(mode: u32) -> AccessMask {
    let mut mask = 0u32;

    if mode & 0o4 != 0 {
        mask |= AccessMask::FILE_GENERIC_READ;
    }
    if mode & 0o2 != 0 {
        mask |= AccessMask::FILE_GENERIC_WRITE;
    }
    if mode & 0o1 != 0 {
        mask |= AccessMask::FILE_GENERIC_EXECUTE;
    }

    AccessMask::new(mask)
}

/// Convert access mask to POSIX mode bits
fn mask_to_mode(mask: AccessMask) -> u32 {
    let mut mode = 0u32;

    if mask.contains(AccessMask::FILE_READ_DATA) {
        mode |= 0o4;
    }
    if mask.contains(AccessMask::FILE_WRITE_DATA) {
        mode |= 0o2;
    }
    if mask.contains(AccessMask::FILE_EXECUTE) {
        mode |= 0o1;
    }

    mode
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sid_well_known() {
        let everyone = Sid::everyone();
        assert_eq!(everyone.to_string(), "S-1-1-0");

        let admins = Sid::administrators();
        assert_eq!(admins.to_string(), "S-1-5-32-544");
    }

    #[test]
    fn test_sid_from_uid() {
        let sid = Sid::from_uid(1000);
        assert_eq!(sid.to_string(), "S-1-22-1-1000");
        assert_eq!(sid.to_uid(), Some(1000));
    }

    #[test]
    fn test_sid_from_gid() {
        let sid = Sid::from_gid(100);
        assert_eq!(sid.to_string(), "S-1-22-2-100");
        assert_eq!(sid.to_gid(), Some(100));
    }

    #[test]
    fn test_security_descriptor_from_posix() {
        let sd = SecurityDescriptor::from_posix(1000, 100, 0o755);

        assert!(sd.owner.is_some());
        assert!(sd.group.is_some());
        assert!(sd.dacl.is_some());

        let mode = sd.to_posix_mode();
        assert_eq!(mode & 0o700, 0o700); // Owner has rwx
        assert_eq!(mode & 0o070, 0o050); // Group has rx
        assert_eq!(mode & 0o007, 0o005); // Other has rx
    }

    #[test]
    fn test_access_mask() {
        let mask = AccessMask::full_control();
        assert!(mask.contains(AccessMask::FILE_READ_DATA));
        assert!(mask.contains(AccessMask::FILE_WRITE_DATA));
        assert!(mask.contains(AccessMask::DELETE));
    }
}
