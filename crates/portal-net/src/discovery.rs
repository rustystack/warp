//! mDNS peer discovery for Portal mesh network
//!
//! Provides local network peer discovery using multicast DNS (mDNS).
//! Peers announce their presence and discover each other automatically.
//!
//! Service type: `_portal._udp.local.` containing public key, virtual IP, and endpoint.

use mdns_sd::{ServiceDaemon, ServiceInfo};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

use crate::types::{MdnsConfig, VirtualIp};
use crate::{PortalNetError, Result};

/// Service type for Portal mDNS announcements
const SERVICE_TYPE: &str = "_portal._udp.local.";

/// TXT record key for public key
const TXT_KEY_PUBLIC_KEY: &str = "public_key";

/// TXT record key for virtual IP
const TXT_KEY_VIRTUAL_IP: &str = "virtual_ip";

/// Local edge information for mDNS registration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEdgeInfo {
    /// `WireGuard` public key (X25519)
    pub public_key: [u8; 32],
    /// Virtual IP in Portal subnet
    pub virtual_ip: VirtualIp,
    /// QUIC endpoint for P2P
    pub endpoint: SocketAddr,
}

impl LocalEdgeInfo {
    /// Creates a new `LocalEdgeInfo` instance
    #[must_use]
    pub const fn new(public_key: [u8; 32], virtual_ip: VirtualIp, endpoint: SocketAddr) -> Self {
        Self {
            public_key,
            virtual_ip,
            endpoint,
        }
    }

    /// Returns the public key as hex
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Validates the `LocalEdgeInfo`
    ///
    /// # Errors
    ///
    /// Returns an error if the virtual IP is not in the Portal subnet
    pub fn validate(&self) -> Result<()> {
        if !self.virtual_ip.is_portal_subnet() {
            return Err(PortalNetError::InvalidVirtualIp(format!(
                "{} is not in the Portal subnet",
                self.virtual_ip
            )));
        }
        Ok(())
    }
}

/// Events emitted during peer discovery
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// A peer was discovered on the local network
    PeerDiscovered {
        /// `WireGuard` public key of the discovered peer
        public_key: [u8; 32],
        /// Virtual IP address assigned to the peer in the Portal subnet
        virtual_ip: VirtualIp,
        /// Network endpoint (`IP:port`) where the peer can be reached
        endpoint: SocketAddr,
    },
    /// A peer was lost (no longer responding)
    PeerLost {
        /// `WireGuard` public key of the lost peer
        public_key: [u8; 32],
    },
}

impl DiscoveryEvent {
    /// Returns the public key associated with this event
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        match self {
            Self::PeerDiscovered { public_key, .. } | Self::PeerLost { public_key } => public_key,
        }
    }
}

/// Internal state for the discovery service
struct DiscoveryState {
    /// mDNS service daemon
    daemon: ServiceDaemon,
    /// Currently registered service instance
    registered_service: Option<String>,
    /// Known peers (public_key -> instance_name)
    known_peers: HashMap<[u8; 32], String>,
}

/// mDNS discovery service for Portal mesh network
pub struct MdnsDiscovery {
    config: MdnsConfig,
    state: Arc<RwLock<DiscoveryState>>,
}

impl MdnsDiscovery {
    /// Creates a new mDNS discovery service
    ///
    /// # Errors
    ///
    /// Returns an error if the mDNS daemon fails to create
    pub fn new(config: MdnsConfig) -> Result<Self> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| PortalNetError::Mdns(format!("failed to create mDNS daemon: {e}")))?;

        let state = DiscoveryState {
            daemon,
            registered_service: None,
            known_peers: HashMap::new(),
        };

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Registers the local edge for mDNS discovery
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails or the virtual IP is invalid
    pub async fn register(&self, local_edge: &LocalEdgeInfo) -> Result<()> {
        local_edge.validate()?;

        let mut state = self.state.write().await;

        // Unregister existing service if present
        if let Some(instance_name) = &state.registered_service {
            state
                .daemon
                .unregister(instance_name)
                .map_err(|e| PortalNetError::Mdns(format!("failed to unregister: {e}")))?;
            state.registered_service = None;
        }

        // Create instance name from public key
        let instance_name = format!("portal-{}", hex::encode(&local_edge.public_key[..8]));

        // Build TXT properties
        let mut properties = HashMap::new();
        properties.insert(
            TXT_KEY_PUBLIC_KEY.to_string(),
            hex::encode(local_edge.public_key),
        );
        properties.insert(
            TXT_KEY_VIRTUAL_IP.to_string(),
            local_edge.virtual_ip.to_string(),
        );

        // Extract host IP from endpoint
        let host_ip_str = match local_edge.endpoint.ip() {
            IpAddr::V4(ipv4) => ipv4.to_string(),
            IpAddr::V6(_) => {
                return Err(PortalNetError::Configuration(
                    "IPv6 endpoints not supported for mDNS".to_string(),
                ));
            }
        };

        // Create service info
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &format!("{instance_name}.local."),
            host_ip_str.as_str(),
            local_edge.endpoint.port(),
            Some(properties),
        )
        .map_err(|e| PortalNetError::Mdns(format!("failed to create service info: {e}")))?;

        // Register the service
        state
            .daemon
            .register(service_info)
            .map_err(|e| PortalNetError::Mdns(format!("failed to register service: {e}")))?;

        state.registered_service = Some(instance_name);

        Ok(())
    }

    /// Starts browsing for peers and returns an event receiver
    ///
    /// # Errors
    ///
    /// Returns an error if browsing fails to start
    pub async fn browse(&self) -> Result<mpsc::Receiver<DiscoveryEvent>> {
        let (tx, rx) = mpsc::channel(100);
        let state = self.state.clone();

        // Get the receiver from the daemon
        let receiver = {
            let state_guard = state.read().await;
            state_guard
                .daemon
                .browse(SERVICE_TYPE)
                .map_err(|e| PortalNetError::Mdns(format!("failed to start browsing: {e}")))?
        };

        // Spawn background task to process mDNS events
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                match event {
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        if let Some(discovery_event) = Self::process_resolved(&info, &state).await {
                            let _ = tx.send(discovery_event).await;
                        }
                    }
                    mdns_sd::ServiceEvent::ServiceRemoved(_, instance_name) => {
                        if let Some(discovery_event) =
                            Self::process_removed(&instance_name, &state).await
                        {
                            let _ = tx.send(discovery_event).await;
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(rx)
    }

    /// Stops discovery and unregisters the local service
    ///
    /// # Errors
    ///
    /// Returns an error if unregistration or shutdown fails
    pub async fn stop(&self) -> Result<()> {
        let mut state = self.state.write().await;

        if let Some(instance_name) = state.registered_service.take() {
            state
                .daemon
                .unregister(&instance_name)
                .map_err(|e| PortalNetError::Mdns(format!("failed to unregister: {e}")))?;
        }

        state
            .daemon
            .shutdown()
            .map_err(|e| PortalNetError::Mdns(format!("failed to shutdown daemon: {e}")))?;

        Ok(())
    }

    /// Processes a resolved service and generates a discovery event
    async fn process_resolved(
        info: &ServiceInfo,
        state: &Arc<RwLock<DiscoveryState>>,
    ) -> Option<DiscoveryEvent> {
        // Extract TXT properties
        let properties = info.get_properties();

        // Parse public key
        let public_key_hex = properties.get(TXT_KEY_PUBLIC_KEY)?;
        let public_key_str = public_key_hex.val_str();
        let public_key_bytes = hex::decode(public_key_str).ok()?;
        if public_key_bytes.len() != 32 {
            return None;
        }
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public_key_bytes);

        // Parse virtual IP
        let virtual_ip_txt = properties.get(TXT_KEY_VIRTUAL_IP)?;
        let virtual_ip_str = virtual_ip_txt.val_str();
        let ipv4: std::net::Ipv4Addr = virtual_ip_str.parse().ok()?;
        let virtual_ip = VirtualIp::from_ipv4(ipv4).ok()?;

        // Get endpoint from service info
        let addresses = info.get_addresses();
        let port = info.get_port();

        if addresses.is_empty() {
            return None;
        }

        let endpoint = SocketAddr::new(*addresses.iter().next()?, port);

        // Update known peers
        let mut state_guard = state.write().await;
        state_guard
            .known_peers
            .insert(public_key, info.get_fullname().to_string());
        drop(state_guard);

        Some(DiscoveryEvent::PeerDiscovered {
            public_key,
            virtual_ip,
            endpoint,
        })
    }

    /// Processes a removed service and generates a discovery event
    async fn process_removed(
        instance_name: &str,
        state: &Arc<RwLock<DiscoveryState>>,
    ) -> Option<DiscoveryEvent> {
        let mut state_guard = state.write().await;

        // Find the peer with this instance name
        let public_key = state_guard
            .known_peers
            .iter()
            .find(|(_, name)| name.as_str() == instance_name)
            .map(|(key, _)| *key)?;

        // Remove from known peers
        state_guard.known_peers.remove(&public_key);

        Some(DiscoveryEvent::PeerLost { public_key })
    }

    /// Returns the current configuration
    #[must_use]
    pub const fn config(&self) -> &MdnsConfig {
        &self.config
    }

    /// Returns the number of known peers
    pub async fn peer_count(&self) -> usize {
        let state = self.state.read().await;
        state.known_peers.len()
    }

    /// Checks if a service is currently registered
    pub async fn is_registered(&self) -> bool {
        let state = self.state.read().await;
        state.registered_service.is_some()
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        // Best-effort cleanup - we can't await in Drop
        if let Ok(state) = self.state.try_read() {
            if let Some(instance_name) = &state.registered_service {
                let _ = state.daemon.unregister(instance_name);
            }
            let _ = state.daemon.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_local_edge_info() {
        let public_key = [1u8; 32];
        let edge = LocalEdgeInfo::new(
            public_key,
            VirtualIp::new(100),
            "192.168.1.10:51820".parse().unwrap(),
        );
        assert_eq!(edge.public_key, public_key);
        assert_eq!(edge.virtual_ip, VirtualIp::new(100));
        assert!(edge.validate().is_ok());

        let hex = LocalEdgeInfo::new(
            [0xAB; 32],
            VirtualIp::new(50),
            "127.0.0.1:51820".parse().unwrap(),
        )
        .public_key_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "ab".repeat(32));

        let edge1 = LocalEdgeInfo::new(
            [1u8; 32],
            VirtualIp::new(100),
            "192.168.1.10:51820".parse().unwrap(),
        );
        let edge2 = edge1.clone();
        let edge3 = LocalEdgeInfo::new(
            [2u8; 32],
            VirtualIp::new(100),
            "192.168.1.10:51820".parse().unwrap(),
        );
        assert_eq!(edge1, edge2);
        assert_ne!(edge1, edge3);

        use std::net::Ipv4Addr;
        let invalid_vip = VirtualIp::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(invalid_vip.is_err());
    }

    #[test]
    fn test_discovery_event() {
        let event1 = DiscoveryEvent::PeerDiscovered {
            public_key: [1u8; 32],
            virtual_ip: VirtualIp::new(100),
            endpoint: "192.168.1.10:51820".parse().unwrap(),
        };
        assert_eq!(event1.public_key(), &[1u8; 32]);

        let event2 = DiscoveryEvent::PeerLost {
            public_key: [2u8; 32],
        };
        assert_eq!(event2.public_key(), &[2u8; 32]);

        let event3 = event1.clone();
        assert_eq!(event1, event3);
        assert_ne!(event1, event2);
    }

    #[test]
    fn test_mdns_discovery_new() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config.clone()).unwrap();
        assert_eq!(discovery.config().service_name, config.service_name);

        let mut custom_config = MdnsConfig::default();
        custom_config.service_name = "_test._udp.local".to_string();
        custom_config.announce_interval_secs = 30;
        let discovery = MdnsDiscovery::new(custom_config.clone()).unwrap();
        assert_eq!(discovery.config().service_name, "_test._udp.local");
        assert_eq!(discovery.config().announce_interval_secs, 30);
    }

    #[tokio::test]
    async fn test_mdns_discovery_register() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        let edge = LocalEdgeInfo::new(
            [1u8; 32],
            VirtualIp::new(100),
            "127.0.0.1:51820".parse().unwrap(),
        );

        let result = discovery.register(&edge).await;
        assert!(result.is_ok());

        assert!(discovery.is_registered().await);
    }

    #[tokio::test]
    async fn test_mdns_discovery_register_twice() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        let edge1 = LocalEdgeInfo::new(
            [1u8; 32],
            VirtualIp::new(100),
            "127.0.0.1:51820".parse().unwrap(),
        );

        discovery.register(&edge1).await.unwrap();

        // Registering again should succeed (unregisters previous)
        let edge2 = LocalEdgeInfo::new(
            [2u8; 32],
            VirtualIp::new(101),
            "127.0.0.1:51821".parse().unwrap(),
        );

        let result = discovery.register(&edge2).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_discovery_register_ipv6_error() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        let edge = LocalEdgeInfo::new(
            [1u8; 32],
            VirtualIp::new(100),
            "[::1]:51820".parse().unwrap(),
        );

        let result = discovery.register(&edge).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(PortalNetError::Configuration(_))));
    }

    #[tokio::test]
    async fn test_mdns_discovery_browse() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        let rx = discovery.browse().await;
        assert!(rx.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_discovery_stop() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        let edge = LocalEdgeInfo::new(
            [1u8; 32],
            VirtualIp::new(100),
            "127.0.0.1:51820".parse().unwrap(),
        );

        discovery.register(&edge).await.unwrap();
        assert!(discovery.is_registered().await);

        let result = discovery.stop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_discovery_state() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();
        assert_eq!(discovery.peer_count().await, 0);
        assert!(!discovery.is_registered().await);
    }

    #[tokio::test]
    async fn test_mdns_discovery_concurrent_browse() {
        let config = MdnsConfig::default();
        let discovery = Arc::new(MdnsDiscovery::new(config).unwrap());

        let discovery1 = discovery.clone();
        let handle1 = tokio::spawn(async move { discovery1.browse().await });

        let discovery2 = discovery.clone();
        let handle2 = tokio::spawn(async move { discovery2.browse().await });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_discovery_register_unregister_flow() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        // Initial state
        assert!(!discovery.is_registered().await);
        assert_eq!(discovery.peer_count().await, 0);

        // Register
        let edge = LocalEdgeInfo::new(
            [1u8; 32],
            VirtualIp::new(100),
            "127.0.0.1:51820".parse().unwrap(),
        );
        discovery.register(&edge).await.unwrap();
        assert!(discovery.is_registered().await);

        // Stop (unregister)
        discovery.stop().await.unwrap();
    }

    #[test]
    fn test_constants_and_debug() {
        assert_eq!(SERVICE_TYPE, "_portal._udp.local.");
        assert_eq!(TXT_KEY_PUBLIC_KEY, "public_key");
        assert_eq!(TXT_KEY_VIRTUAL_IP, "virtual_ip");

        let edge = LocalEdgeInfo::new(
            [1u8; 32],
            VirtualIp::new(100),
            "192.168.1.10:51820".parse().unwrap(),
        );
        let debug_str = format!("{:?}", edge);
        assert!(debug_str.contains("LocalEdgeInfo"));

        let event = DiscoveryEvent::PeerDiscovered {
            public_key: [1u8; 32],
            virtual_ip: VirtualIp::new(100),
            endpoint: "192.168.1.10:51820".parse().unwrap(),
        };
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("PeerDiscovered"));
    }

    #[tokio::test]
    async fn test_mdns_discovery_multiple_registrations() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        let edges = vec![
            LocalEdgeInfo::new(
                [1u8; 32],
                VirtualIp::new(100),
                "127.0.0.1:51820".parse().unwrap(),
            ),
            LocalEdgeInfo::new(
                [2u8; 32],
                VirtualIp::new(101),
                "127.0.0.1:51821".parse().unwrap(),
            ),
            LocalEdgeInfo::new(
                [3u8; 32],
                VirtualIp::new(102),
                "127.0.0.1:51822".parse().unwrap(),
            ),
        ];

        for edge in edges {
            let result = discovery.register(&edge).await;
            assert!(result.is_ok());
            assert!(discovery.is_registered().await);
        }
    }

    #[tokio::test]
    async fn test_mdns_discovery_config_access() {
        let mut config = MdnsConfig::default();
        config.announce_interval_secs = 120;
        config.scan_interval_secs = 60;

        let discovery = MdnsDiscovery::new(config.clone()).unwrap();

        assert_eq!(
            discovery.config().announce_interval_secs,
            config.announce_interval_secs
        );
        assert_eq!(
            discovery.config().scan_interval_secs,
            config.scan_interval_secs
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_mdns_discovery_concurrent_operations() {
        let config = MdnsConfig::default();
        let discovery = Arc::new(MdnsDiscovery::new(config).unwrap());

        let mut count_handles = vec![];
        let mut reg_handles = vec![];

        // Concurrent peer count checks
        for _ in 0..10 {
            let d = discovery.clone();
            count_handles.push(tokio::spawn(async move { d.peer_count().await }));
        }

        // Concurrent is_registered checks
        for _ in 0..10 {
            let d = discovery.clone();
            reg_handles.push(tokio::spawn(async move { d.is_registered().await }));
        }

        for handle in count_handles {
            handle.await.unwrap();
        }

        for handle in reg_handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_mdns_discovery_edge_cases() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        // Edge case: VirtualIp with host 0
        let edge = LocalEdgeInfo::new(
            [0u8; 32],
            VirtualIp::new(0),
            "127.0.0.1:51820".parse().unwrap(),
        );
        assert!(discovery.register(&edge).await.is_ok());

        // Edge case: VirtualIp with max host
        let edge = LocalEdgeInfo::new(
            [255u8; 32],
            VirtualIp::new(u16::MAX),
            "127.0.0.1:51820".parse().unwrap(),
        );
        assert!(discovery.register(&edge).await.is_ok());
    }

    #[tokio::test]
    async fn test_mdns_discovery_browse_timeout() {
        let config = MdnsConfig::default();
        let discovery = MdnsDiscovery::new(config).unwrap();

        let mut rx = discovery.browse().await.unwrap();

        // Wait briefly - should not receive any events on clean network
        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(result.is_err()); // Timeout expected
    }
}
