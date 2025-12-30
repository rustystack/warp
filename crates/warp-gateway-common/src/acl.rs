//! ACL translation layer for protocol gateways
//!
//! Provides translation between POSIX (mode bits, uid/gid) and
//! Windows (SID, DACL) access control mechanisms.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Principal identifier (works for both POSIX and Windows)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrincipalId {
    /// POSIX user ID
    PosixUid(u32),
    /// POSIX group ID
    PosixGid(u32),
    /// Windows Security Identifier
    WindowsSid(Vec<u8>),
    /// Everyone (world-readable)
    Everyone,
    /// Owner (special placeholder)
    Owner,
    /// Owning group (special placeholder)
    OwningGroup,
}

impl PrincipalId {
    /// Create from POSIX UID
    pub fn from_uid(uid: u32) -> Self {
        Self::PosixUid(uid)
    }

    /// Create from POSIX GID
    pub fn from_gid(gid: u32) -> Self {
        Self::PosixGid(gid)
    }

    /// Create from Windows SID bytes
    pub fn from_sid(sid: Vec<u8>) -> Self {
        Self::WindowsSid(sid)
    }

    /// Check if this is the owner
    pub fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }

    /// Check if this is the owning group
    pub fn is_group(&self) -> bool {
        matches!(self, Self::OwningGroup)
    }

    /// Check if this is everyone
    pub fn is_everyone(&self) -> bool {
        matches!(self, Self::Everyone)
    }
}

/// Access type (Allow or Deny)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessType {
    /// Allow access
    Allow,
    /// Deny access
    Deny,
}

/// ACL permissions bitmask
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclPermissions(u32);

impl AclPermissions {
    /// No permissions
    pub const NONE: Self = Self(0);

    // File permissions
    /// Read data
    pub const READ_DATA: Self = Self(0x0001);
    /// Write data
    pub const WRITE_DATA: Self = Self(0x0002);
    /// Append data
    pub const APPEND_DATA: Self = Self(0x0004);
    /// Read extended attributes
    pub const READ_EA: Self = Self(0x0008);
    /// Write extended attributes
    pub const WRITE_EA: Self = Self(0x0010);
    /// Execute
    pub const EXECUTE: Self = Self(0x0020);
    /// Delete child (for directories)
    pub const DELETE_CHILD: Self = Self(0x0040);
    /// Read attributes
    pub const READ_ATTRS: Self = Self(0x0080);
    /// Write attributes
    pub const WRITE_ATTRS: Self = Self(0x0100);

    // Standard permissions
    /// Delete
    pub const DELETE: Self = Self(0x00010000);
    /// Read control (read security descriptor)
    pub const READ_CONTROL: Self = Self(0x00020000);
    /// Write DAC (modify DACL)
    pub const WRITE_DAC: Self = Self(0x00040000);
    /// Write owner
    pub const WRITE_OWNER: Self = Self(0x00080000);
    /// Synchronize
    pub const SYNCHRONIZE: Self = Self(0x00100000);

    // Combined permissions
    /// Full control
    pub const FULL_CONTROL: Self = Self(0x001F01FF);
    /// Read (combination)
    pub const READ: Self = Self(0x00020089);
    /// Write (combination)
    pub const WRITE: Self = Self(0x00020116);

    /// Create new permissions from raw value
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get raw value
    pub const fn value(&self) -> u32 {
        self.0
    }

    /// Check if permission is set
    pub const fn has(&self, perm: Self) -> bool {
        (self.0 & perm.0) == perm.0
    }

    /// Add permission
    pub const fn with(self, perm: Self) -> Self {
        Self(self.0 | perm.0)
    }

    /// Remove permission
    pub const fn without(self, perm: Self) -> Self {
        Self(self.0 & !perm.0)
    }

    /// Create from POSIX mode bits (for owner, group, or other)
    pub fn from_posix_mode(mode: u32, shift: u32) -> Self {
        let bits = (mode >> shift) & 0o7;
        let mut perms = Self::NONE;

        if bits & 0o4 != 0 {
            perms = perms.with(Self::READ_DATA).with(Self::READ_ATTRS);
        }
        if bits & 0o2 != 0 {
            perms = perms.with(Self::WRITE_DATA).with(Self::APPEND_DATA).with(Self::WRITE_ATTRS);
        }
        if bits & 0o1 != 0 {
            perms = perms.with(Self::EXECUTE);
        }

        perms
    }

    /// Convert to POSIX mode bits
    pub fn to_posix_bits(&self) -> u32 {
        let mut bits = 0u32;

        if self.has(Self::READ_DATA) {
            bits |= 0o4;
        }
        if self.has(Self::WRITE_DATA) {
            bits |= 0o2;
        }
        if self.has(Self::EXECUTE) {
            bits |= 0o1;
        }

        bits
    }
}

/// ACL entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    /// Principal this entry applies to
    pub principal: PrincipalId,
    /// Allow or deny
    pub access_type: AccessType,
    /// Permissions
    pub permissions: AclPermissions,
    /// Flags (inheritance, etc.)
    pub flags: u32,
}

impl AclEntry {
    /// Create a new ACL entry
    pub fn new(principal: PrincipalId, access_type: AccessType, permissions: AclPermissions) -> Self {
        Self {
            principal,
            access_type,
            permissions,
            flags: 0,
        }
    }

    /// Create an allow entry
    pub fn allow(principal: PrincipalId, permissions: AclPermissions) -> Self {
        Self::new(principal, AccessType::Allow, permissions)
    }

    /// Create a deny entry
    pub fn deny(principal: PrincipalId, permissions: AclPermissions) -> Self {
        Self::new(principal, AccessType::Deny, permissions)
    }
}

/// Unified ACL representation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnifiedAcl {
    /// Owner principal
    pub owner: Option<PrincipalId>,
    /// Group principal
    pub group: Option<PrincipalId>,
    /// ACL entries
    pub entries: Vec<AclEntry>,
}

impl UnifiedAcl {
    /// Create a new empty ACL
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from POSIX mode, uid, and gid
    pub fn from_posix(mode: u32, uid: u32, gid: u32) -> Self {
        let mut acl = Self::new();
        acl.owner = Some(PrincipalId::PosixUid(uid));
        acl.group = Some(PrincipalId::PosixGid(gid));

        // Owner permissions
        acl.entries.push(AclEntry::allow(
            PrincipalId::Owner,
            AclPermissions::from_posix_mode(mode, 6),
        ));

        // Group permissions
        acl.entries.push(AclEntry::allow(
            PrincipalId::OwningGroup,
            AclPermissions::from_posix_mode(mode, 3),
        ));

        // Other permissions
        acl.entries.push(AclEntry::allow(
            PrincipalId::Everyone,
            AclPermissions::from_posix_mode(mode, 0),
        ));

        acl
    }

    /// Convert to POSIX mode bits
    pub fn to_posix_mode(&self) -> u32 {
        let mut mode = 0u32;

        for entry in &self.entries {
            if entry.access_type != AccessType::Allow {
                continue;
            }

            let bits = entry.permissions.to_posix_bits();
            match &entry.principal {
                PrincipalId::Owner => mode |= bits << 6,
                PrincipalId::OwningGroup => mode |= bits << 3,
                PrincipalId::Everyone => mode |= bits,
                _ => {}
            }
        }

        mode
    }

    /// Add an entry
    pub fn add_entry(&mut self, entry: AclEntry) {
        self.entries.push(entry);
    }
}

/// Windows Security Descriptor (simplified)
#[derive(Debug, Clone, Default)]
pub struct WindowsSecurityDescriptor {
    /// Owner SID
    pub owner_sid: Option<Vec<u8>>,
    /// Group SID
    pub group_sid: Option<Vec<u8>>,
    /// DACL entries
    pub dacl: Vec<AclEntry>,
    /// SACL entries (for auditing)
    pub sacl: Vec<AclEntry>,
}

/// Well-known SIDs
pub struct WellKnownSids;

impl WellKnownSids {
    /// Everyone (S-1-1-0)
    pub const EVERYONE: &'static [u8] = &[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    /// Authenticated Users (S-1-5-11)
    pub const AUTHENTICATED_USERS: &'static [u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
    /// BUILTIN\Administrators (S-1-5-32-544)
    pub const ADMINISTRATORS: &'static [u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
}

/// ACL translator for POSIX ↔ Windows conversion
pub struct AclTranslator {
    /// UID to SID mapping cache
    uid_to_sid: HashMap<u32, Vec<u8>>,
    /// SID to UID mapping cache
    sid_to_uid: HashMap<Vec<u8>, u32>,
    /// GID to SID mapping cache
    gid_to_sid: HashMap<u32, Vec<u8>>,
    /// SID to GID mapping cache
    sid_to_gid: HashMap<Vec<u8>, u32>,
}

impl AclTranslator {
    /// Create a new translator
    pub fn new() -> Self {
        Self {
            uid_to_sid: HashMap::new(),
            sid_to_uid: HashMap::new(),
            gid_to_sid: HashMap::new(),
            sid_to_gid: HashMap::new(),
        }
    }

    /// Convert POSIX mode to Windows security descriptor
    pub fn posix_to_windows(&self, mode: u32, uid: u32, gid: u32) -> WindowsSecurityDescriptor {
        let mut sd = WindowsSecurityDescriptor::default();

        // Map owner UID to SID (or create synthetic)
        sd.owner_sid = self.uid_to_sid.get(&uid).cloned().or_else(|| {
            Some(self.create_posix_sid(uid, false))
        });

        // Map group GID to SID
        sd.group_sid = self.gid_to_sid.get(&gid).cloned().or_else(|| {
            Some(self.create_posix_sid(gid, true))
        });

        // Convert mode bits to DACL
        // Owner ACE
        if let Some(ref owner_sid) = sd.owner_sid {
            sd.dacl.push(AclEntry::allow(
                PrincipalId::WindowsSid(owner_sid.clone()),
                AclPermissions::from_posix_mode(mode, 6),
            ));
        }

        // Group ACE
        if let Some(ref group_sid) = sd.group_sid {
            sd.dacl.push(AclEntry::allow(
                PrincipalId::WindowsSid(group_sid.clone()),
                AclPermissions::from_posix_mode(mode, 3),
            ));
        }

        // Everyone ACE
        sd.dacl.push(AclEntry::allow(
            PrincipalId::WindowsSid(WellKnownSids::EVERYONE.to_vec()),
            AclPermissions::from_posix_mode(mode, 0),
        ));

        sd
    }

    /// Convert Windows security descriptor to POSIX mode, uid, gid
    pub fn windows_to_posix(&self, sd: &WindowsSecurityDescriptor) -> (u32, u32, u32) {
        // Extract UID from owner SID
        let uid = sd.owner_sid.as_ref().and_then(|sid| {
            self.sid_to_uid.get(sid).copied().or_else(|| {
                self.extract_posix_id(sid, false)
            })
        }).unwrap_or(0);

        // Extract GID from group SID
        let gid = sd.group_sid.as_ref().and_then(|sid| {
            self.sid_to_gid.get(sid).copied().or_else(|| {
                self.extract_posix_id(sid, true)
            })
        }).unwrap_or(0);

        // Calculate mode from DACL
        let mut mode = 0u32;
        for entry in &sd.dacl {
            if entry.access_type != AccessType::Allow {
                continue;
            }

            let bits = entry.permissions.to_posix_bits();
            match &entry.principal {
                PrincipalId::WindowsSid(sid) if Some(sid) == sd.owner_sid.as_ref() => {
                    mode |= bits << 6;
                }
                PrincipalId::WindowsSid(sid) if Some(sid) == sd.group_sid.as_ref() => {
                    mode |= bits << 3;
                }
                PrincipalId::WindowsSid(sid) if sid == WellKnownSids::EVERYONE => {
                    mode |= bits;
                }
                PrincipalId::Everyone => {
                    mode |= bits;
                }
                _ => {}
            }
        }

        (mode, uid, gid)
    }

    /// Convert any ACL to unified representation
    pub fn to_unified(&self, mode: u32, uid: u32, gid: u32) -> UnifiedAcl {
        UnifiedAcl::from_posix(mode, uid, gid)
    }

    /// Create a synthetic SID for a POSIX ID
    /// Format: S-1-22-{1|2}-{id}
    /// 1 = UID, 2 = GID
    fn create_posix_sid(&self, id: u32, is_group: bool) -> Vec<u8> {
        let mut sid = vec![1u8, 2]; // Revision 1, 2 sub-authorities

        // Identifier authority: 22 (custom for POSIX)
        sid.extend_from_slice(&[0, 0, 0, 0, 0, 22]);

        // Sub-authority 1: 1 for UID, 2 for GID
        let type_id: u32 = if is_group { 2 } else { 1 };
        sid.extend_from_slice(&type_id.to_le_bytes());

        // Sub-authority 2: the actual ID
        sid.extend_from_slice(&id.to_le_bytes());

        sid
    }

    /// Extract POSIX ID from synthetic SID
    fn extract_posix_id(&self, sid: &[u8], _is_group: bool) -> Option<u32> {
        // Check for our synthetic POSIX SID format
        if sid.len() >= 16 && sid[0] == 1 && sid[1] == 2 {
            // Check authority is 22
            if sid[7] == 22 {
                // Extract the ID from sub-authority 2
                if let Ok(bytes) = sid[12..16].try_into() {
                    return Some(u32::from_le_bytes(bytes));
                }
            }
        }
        None
    }

    /// Register a UID to SID mapping
    pub fn register_uid(&mut self, uid: u32, sid: Vec<u8>) {
        self.sid_to_uid.insert(sid.clone(), uid);
        self.uid_to_sid.insert(uid, sid);
    }

    /// Register a GID to SID mapping
    pub fn register_gid(&mut self, gid: u32, sid: Vec<u8>) {
        self.sid_to_gid.insert(sid.clone(), gid);
        self.gid_to_sid.insert(gid, sid);
    }
}

impl Default for AclTranslator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_posix_mode_conversion() {
        let acl = UnifiedAcl::from_posix(0o755, 1000, 1000);
        assert_eq!(acl.to_posix_mode(), 0o755);

        let acl = UnifiedAcl::from_posix(0o644, 0, 0);
        assert_eq!(acl.to_posix_mode(), 0o644);
    }

    #[test]
    fn test_permissions() {
        let perms = AclPermissions::READ_DATA.with(AclPermissions::WRITE_DATA);
        assert!(perms.has(AclPermissions::READ_DATA));
        assert!(perms.has(AclPermissions::WRITE_DATA));
        assert!(!perms.has(AclPermissions::EXECUTE));

        let perms = perms.without(AclPermissions::WRITE_DATA);
        assert!(!perms.has(AclPermissions::WRITE_DATA));
    }

    #[test]
    fn test_translator_roundtrip() {
        let translator = AclTranslator::new();

        let sd = translator.posix_to_windows(0o755, 1000, 1000);
        let (mode, uid, gid) = translator.windows_to_posix(&sd);

        assert_eq!(mode, 0o755);
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1000);
    }
}
