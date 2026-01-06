//! S3-Compatible Event Notifications
//!
//! Implements event notifications for object storage operations, compatible with
//! AWS S3 event notification format. Integrates with HPC-Channels for ecosystem-wide
//! event distribution.
//!
//! ## Supported Events
//!
//! - `s3:ObjectCreated:*` - Object created (Put, Post, Copy, CompleteMultipartUpload)
//! - `s3:ObjectRemoved:*` - Object deleted (Delete, DeleteMarkerCreated)
//! - `s3:ObjectRestore:*` - Object restored from archive
//! - `s3:LifecycleExpiration:*` - Object expired by lifecycle rule
//! - `s3:LifecycleTransition` - Object transitioned to different storage class
//!
//! ## Integration with HPC-Channels
//!
//! Events are published to the broadcast channel `hpc.storage.events` and can be
//! subscribed to by any service in the HPC-AI ecosystem (Horizon, RustySpark, etc.)
//!
//! ## Example
//!
//! ```rust,no_run
//! use warp_store::events::{EventEmitter, EventConfig, S3Event};
//!
//! // Create event emitter
//! let emitter = EventEmitter::new(EventConfig::default());
//!
//! // Subscribe to events
//! let mut rx = emitter.subscribe();
//!
//! // Process events
//! tokio::spawn(async move {
//!     while let Ok(event) = rx.recv().await {
//!         println!("Event: {:?}", event.event_name);
//!     }
//! });
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

#[cfg(feature = "hpc-channels")]
use hpc_channels::{
    StorageBucketInfo, StorageEventMessage, StorageEventRecord, StorageObjectInfo,
    StorageUserIdentity, broadcast as hpc_broadcast, channels,
};

use crate::ObjectKey;

/// Channel capacity for event broadcast
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// HPC-Channels channel ID for storage events
pub const STORAGE_EVENTS_CHANNEL: &str = "hpc.storage.events";

/// S3-compatible event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    // Object Created events
    /// Object created via PUT
    #[serde(rename = "s3:ObjectCreated:Put")]
    ObjectCreatedPut,
    /// Object created via POST
    #[serde(rename = "s3:ObjectCreated:Post")]
    ObjectCreatedPost,
    /// Object created via COPY
    #[serde(rename = "s3:ObjectCreated:Copy")]
    ObjectCreatedCopy,
    /// Object created via multipart upload completion
    #[serde(rename = "s3:ObjectCreated:CompleteMultipartUpload")]
    ObjectCreatedCompleteMultipartUpload,

    // Object Removed events
    /// Object deleted
    #[serde(rename = "s3:ObjectRemoved:Delete")]
    ObjectRemovedDelete,
    /// Delete marker created (versioned bucket)
    #[serde(rename = "s3:ObjectRemoved:DeleteMarkerCreated")]
    ObjectRemovedDeleteMarkerCreated,

    // Object Restore events (from archive)
    /// Restore initiated
    #[serde(rename = "s3:ObjectRestore:Post")]
    ObjectRestorePost,
    /// Restore completed
    #[serde(rename = "s3:ObjectRestore:Completed")]
    ObjectRestoreCompleted,

    // Lifecycle events
    /// Object expired by lifecycle rule
    #[serde(rename = "s3:LifecycleExpiration:Delete")]
    LifecycleExpirationDelete,
    /// Delete marker expired
    #[serde(rename = "s3:LifecycleExpiration:DeleteMarkerCreated")]
    LifecycleExpirationDeleteMarkerCreated,
    /// Object transitioned to different storage class
    #[serde(rename = "s3:LifecycleTransition")]
    LifecycleTransition,

    // Replication events
    /// Object replicated
    #[serde(rename = "s3:Replication:OperationCompletedReplication")]
    ReplicationCompleted,
    /// Replication failed
    #[serde(rename = "s3:Replication:OperationFailedReplication")]
    ReplicationFailed,
}

impl EventType {
    /// Get the S3-compatible event name string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ObjectCreatedPut => "s3:ObjectCreated:Put",
            Self::ObjectCreatedPost => "s3:ObjectCreated:Post",
            Self::ObjectCreatedCopy => "s3:ObjectCreated:Copy",
            Self::ObjectCreatedCompleteMultipartUpload => {
                "s3:ObjectCreated:CompleteMultipartUpload"
            }
            Self::ObjectRemovedDelete => "s3:ObjectRemoved:Delete",
            Self::ObjectRemovedDeleteMarkerCreated => "s3:ObjectRemoved:DeleteMarkerCreated",
            Self::ObjectRestorePost => "s3:ObjectRestore:Post",
            Self::ObjectRestoreCompleted => "s3:ObjectRestore:Completed",
            Self::LifecycleExpirationDelete => "s3:LifecycleExpiration:Delete",
            Self::LifecycleExpirationDeleteMarkerCreated => {
                "s3:LifecycleExpiration:DeleteMarkerCreated"
            }
            Self::LifecycleTransition => "s3:LifecycleTransition",
            Self::ReplicationCompleted => "s3:Replication:OperationCompletedReplication",
            Self::ReplicationFailed => "s3:Replication:OperationFailedReplication",
        }
    }

    /// Check if this event matches a filter pattern (with wildcards)
    pub fn matches(&self, pattern: &str) -> bool {
        let event_str = self.as_str();

        // Exact match
        if event_str == pattern {
            return true;
        }

        // Wildcard patterns
        if pattern == "s3:ObjectCreated:*" {
            return matches!(
                self,
                Self::ObjectCreatedPut
                    | Self::ObjectCreatedPost
                    | Self::ObjectCreatedCopy
                    | Self::ObjectCreatedCompleteMultipartUpload
            );
        }

        if pattern == "s3:ObjectRemoved:*" {
            return matches!(
                self,
                Self::ObjectRemovedDelete | Self::ObjectRemovedDeleteMarkerCreated
            );
        }

        if pattern == "s3:ObjectRestore:*" {
            return matches!(self, Self::ObjectRestorePost | Self::ObjectRestoreCompleted);
        }

        if pattern == "s3:LifecycleExpiration:*" {
            return matches!(
                self,
                Self::LifecycleExpirationDelete | Self::LifecycleExpirationDeleteMarkerCreated
            );
        }

        if pattern == "s3:Replication:*" {
            return matches!(self, Self::ReplicationCompleted | Self::ReplicationFailed);
        }

        // All events
        if pattern == "s3:*" {
            return true;
        }

        false
    }
}

/// S3-compatible event record (matches AWS S3 event format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Event {
    /// Event version
    pub event_version: String,

    /// Event source
    pub event_source: String,

    /// AWS region (or warp region)
    pub aws_region: String,

    /// Event time
    pub event_time: DateTime<Utc>,

    /// Event name (e.g., "s3:ObjectCreated:Put")
    pub event_name: String,

    /// User identity
    pub user_identity: UserIdentity,

    /// Request parameters
    pub request_parameters: RequestParameters,

    /// Response elements
    pub response_elements: ResponseElements,

    /// S3 object information
    pub s3: S3Info,

    /// Glacier event data (for restore events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub glacier_event_data: Option<GlacierEventData>,
}

impl S3Event {
    /// Create a new event for an object operation
    pub fn new(
        event_type: EventType,
        bucket: &str,
        key: &str,
        size: u64,
        etag: &str,
        version_id: Option<String>,
    ) -> Self {
        Self {
            event_version: "2.1".to_string(),
            event_source: "warp:s3".to_string(),
            aws_region: "warp-local".to_string(),
            event_time: Utc::now(),
            event_name: event_type.as_str().to_string(),
            user_identity: UserIdentity {
                principal_id: "WARP".to_string(),
            },
            request_parameters: RequestParameters {
                source_ip_address: "127.0.0.1".to_string(),
            },
            response_elements: ResponseElements {
                x_amz_request_id: uuid::Uuid::new_v4().to_string(),
                x_amz_id_2: uuid::Uuid::new_v4().to_string(),
            },
            s3: S3Info {
                s3_schema_version: "1.0".to_string(),
                configuration_id: "warp-notifications".to_string(),
                bucket: BucketInfo {
                    name: bucket.to_string(),
                    owner_identity: OwnerIdentity {
                        principal_id: "WARP".to_string(),
                    },
                    arn: format!("arn:warp:s3:::{}", bucket),
                },
                object: ObjectInfo {
                    key: key.to_string(),
                    size,
                    etag: etag.to_string(),
                    version_id,
                    sequencer: format!("{:016X}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
                },
            },
            glacier_event_data: None,
        }
    }

    /// Create event for object creation
    pub fn object_created(key: &ObjectKey, size: u64, etag: &str) -> Self {
        Self::new(
            EventType::ObjectCreatedPut,
            key.bucket(),
            key.key(),
            size,
            etag,
            None,
        )
    }

    /// Create event for object deletion
    pub fn object_deleted(key: &ObjectKey) -> Self {
        Self::new(
            EventType::ObjectRemovedDelete,
            key.bucket(),
            key.key(),
            0,
            "",
            None,
        )
    }

    /// Create event for multipart upload completion
    pub fn multipart_completed(key: &ObjectKey, size: u64, etag: &str) -> Self {
        Self::new(
            EventType::ObjectCreatedCompleteMultipartUpload,
            key.bucket(),
            key.key(),
            size,
            etag,
            None,
        )
    }

    /// Create event for lifecycle expiration
    pub fn lifecycle_expired(bucket: &str, key: &str) -> Self {
        Self::new(
            EventType::LifecycleExpirationDelete,
            bucket,
            key,
            0,
            "",
            None,
        )
    }

    /// Create event for lifecycle transition
    pub fn lifecycle_transitioned(
        bucket: &str,
        key: &str,
        size: u64,
        target_storage_class: &str,
    ) -> Self {
        let mut event = Self::new(EventType::LifecycleTransition, bucket, key, size, "", None);
        // Add storage class info to response elements
        event.response_elements.x_amz_id_2 = target_storage_class.to_string();
        event
    }
}

/// User identity information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdentity {
    /// Principal ID
    pub principal_id: String,
}

/// Request parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestParameters {
    /// Source IP address
    pub source_ip_address: String,
}

/// Response elements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseElements {
    /// Request ID
    #[serde(rename = "x-amz-request-id")]
    pub x_amz_request_id: String,

    /// Extended request ID
    #[serde(rename = "x-amz-id-2")]
    pub x_amz_id_2: String,
}

/// S3 object information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Info {
    /// Schema version
    pub s3_schema_version: String,

    /// Notification configuration ID
    pub configuration_id: String,

    /// Bucket information
    pub bucket: BucketInfo,

    /// Object information
    pub object: ObjectInfo,
}

/// Bucket information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketInfo {
    /// Bucket name
    pub name: String,

    /// Owner identity
    pub owner_identity: OwnerIdentity,

    /// Bucket ARN
    pub arn: String,
}

/// Owner identity
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerIdentity {
    /// Principal ID
    pub principal_id: String,
}

/// Object information
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectInfo {
    /// Object key
    pub key: String,

    /// Object size
    pub size: u64,

    /// ETag
    #[serde(rename = "eTag")]
    pub etag: String,

    /// Version ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,

    /// Sequencer
    pub sequencer: String,
}

/// Glacier event data (for restore operations)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GlacierEventData {
    /// Restore event data
    pub restore_event_data: RestoreEventData,
}

/// Restore event data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreEventData {
    /// Lifecycle restoration expiry time
    pub lifecycle_restoration_expiry_time: DateTime<Utc>,

    /// Lifecycle restore storage class
    pub lifecycle_restore_storage_class: String,
}

// =============================================================================
// Event Configuration
// =============================================================================

/// Notification configuration for a bucket
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationConfiguration {
    /// Topic configurations (SNS-style)
    #[serde(default)]
    pub topic_configurations: Vec<TopicConfiguration>,

    /// Queue configurations (SQS-style)
    #[serde(default)]
    pub queue_configurations: Vec<QueueConfiguration>,

    /// Lambda function configurations
    #[serde(default)]
    pub lambda_function_configurations: Vec<LambdaConfiguration>,

    /// HPC-Channels configurations (WARP-specific)
    #[serde(default)]
    pub hpc_channel_configurations: Vec<HpcChannelConfiguration>,

    /// Webhook configurations (HTTP POST)
    #[serde(default)]
    pub webhook_configurations: Vec<WebhookConfiguration>,
}

impl NotificationConfiguration {
    /// Check if any configuration matches the event
    pub fn matches_event(&self, event: &S3Event) -> bool {
        let event_type_str = &event.event_name;
        let key = &event.s3.object.key;

        // Check all configuration types
        self.topic_configurations
            .iter()
            .any(|c| c.matches(event_type_str, key))
            || self
                .queue_configurations
                .iter()
                .any(|c| c.matches(event_type_str, key))
            || self
                .lambda_function_configurations
                .iter()
                .any(|c| c.matches(event_type_str, key))
            || self
                .hpc_channel_configurations
                .iter()
                .any(|c| c.matches(event_type_str, key))
            || self
                .webhook_configurations
                .iter()
                .any(|c| c.matches(event_type_str, key))
    }

    /// Get matching destinations for an event
    pub fn get_destinations(&self, event: &S3Event) -> Vec<EventDestination> {
        let event_type_str = &event.event_name;
        let key = &event.s3.object.key;
        let mut destinations = Vec::new();

        for config in &self.topic_configurations {
            if config.matches(event_type_str, key) {
                destinations.push(EventDestination::Topic(config.topic_arn.clone()));
            }
        }

        for config in &self.queue_configurations {
            if config.matches(event_type_str, key) {
                destinations.push(EventDestination::Queue(config.queue_arn.clone()));
            }
        }

        for config in &self.lambda_function_configurations {
            if config.matches(event_type_str, key) {
                destinations.push(EventDestination::Lambda(config.lambda_function_arn.clone()));
            }
        }

        for config in &self.hpc_channel_configurations {
            if config.matches(event_type_str, key) {
                destinations.push(EventDestination::HpcChannel(config.channel_id.clone()));
            }
        }

        for config in &self.webhook_configurations {
            if config.matches(event_type_str, key) {
                destinations.push(EventDestination::Webhook(config.clone()));
            }
        }

        destinations
    }
}

/// Event destination
#[derive(Debug, Clone)]
pub enum EventDestination {
    /// SNS topic ARN
    Topic(String),
    /// SQS queue ARN
    Queue(String),
    /// Lambda function ARN
    Lambda(String),
    /// HPC-Channels channel ID
    HpcChannel(String),
    /// Webhook (HTTP POST)
    Webhook(WebhookConfiguration),
}

/// Common configuration trait for notification targets
pub trait NotificationTarget {
    /// Get the configuration ID
    fn id(&self) -> &str;

    /// Get the event types
    fn events(&self) -> &[String];

    /// Get the filter rules
    fn filter(&self) -> Option<&FilterRules>;

    /// Check if this configuration matches an event
    fn matches(&self, event_type: &str, key: &str) -> bool {
        // Check event type match
        let event_matches = self.events().iter().any(|pattern| {
            if let Some(et) = parse_event_type(event_type) {
                et.matches(pattern)
            } else {
                false
            }
        });

        if !event_matches {
            return false;
        }

        // Check filter rules
        if let Some(filter) = self.filter() {
            filter.matches(key)
        } else {
            true
        }
    }
}

/// Parse event type string to EventType
fn parse_event_type(s: &str) -> Option<EventType> {
    match s {
        "s3:ObjectCreated:Put" => Some(EventType::ObjectCreatedPut),
        "s3:ObjectCreated:Post" => Some(EventType::ObjectCreatedPost),
        "s3:ObjectCreated:Copy" => Some(EventType::ObjectCreatedCopy),
        "s3:ObjectCreated:CompleteMultipartUpload" => {
            Some(EventType::ObjectCreatedCompleteMultipartUpload)
        }
        "s3:ObjectRemoved:Delete" => Some(EventType::ObjectRemovedDelete),
        "s3:ObjectRemoved:DeleteMarkerCreated" => Some(EventType::ObjectRemovedDeleteMarkerCreated),
        "s3:ObjectRestore:Post" => Some(EventType::ObjectRestorePost),
        "s3:ObjectRestore:Completed" => Some(EventType::ObjectRestoreCompleted),
        "s3:LifecycleExpiration:Delete" => Some(EventType::LifecycleExpirationDelete),
        "s3:LifecycleExpiration:DeleteMarkerCreated" => {
            Some(EventType::LifecycleExpirationDeleteMarkerCreated)
        }
        "s3:LifecycleTransition" => Some(EventType::LifecycleTransition),
        "s3:Replication:OperationCompletedReplication" => Some(EventType::ReplicationCompleted),
        "s3:Replication:OperationFailedReplication" => Some(EventType::ReplicationFailed),
        _ => None,
    }
}

/// Topic configuration (SNS-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicConfiguration {
    /// Configuration ID
    pub id: String,

    /// Topic ARN
    pub topic_arn: String,

    /// Event types to notify
    pub events: Vec<String>,

    /// Filter rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterRules>,
}

impl NotificationTarget for TopicConfiguration {
    fn id(&self) -> &str {
        &self.id
    }
    fn events(&self) -> &[String] {
        &self.events
    }
    fn filter(&self) -> Option<&FilterRules> {
        self.filter.as_ref()
    }
}

/// Queue configuration (SQS-style)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfiguration {
    /// Configuration ID
    pub id: String,

    /// Queue ARN
    pub queue_arn: String,

    /// Event types to notify
    pub events: Vec<String>,

    /// Filter rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterRules>,
}

impl NotificationTarget for QueueConfiguration {
    fn id(&self) -> &str {
        &self.id
    }
    fn events(&self) -> &[String] {
        &self.events
    }
    fn filter(&self) -> Option<&FilterRules> {
        self.filter.as_ref()
    }
}

/// Lambda function configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaConfiguration {
    /// Configuration ID
    pub id: String,

    /// Lambda function ARN
    pub lambda_function_arn: String,

    /// Event types to notify
    pub events: Vec<String>,

    /// Filter rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterRules>,
}

impl NotificationTarget for LambdaConfiguration {
    fn id(&self) -> &str {
        &self.id
    }
    fn events(&self) -> &[String] {
        &self.events
    }
    fn filter(&self) -> Option<&FilterRules> {
        self.filter.as_ref()
    }
}

/// HPC-Channels configuration (WARP-specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpcChannelConfiguration {
    /// Configuration ID
    pub id: String,

    /// HPC-Channels channel ID
    pub channel_id: String,

    /// Event types to notify
    pub events: Vec<String>,

    /// Filter rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterRules>,
}

impl NotificationTarget for HpcChannelConfiguration {
    fn id(&self) -> &str {
        &self.id
    }
    fn events(&self) -> &[String] {
        &self.events
    }
    fn filter(&self) -> Option<&FilterRules> {
        self.filter.as_ref()
    }
}

/// Webhook configuration for HTTP POST notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfiguration {
    /// Configuration ID
    pub id: String,

    /// Webhook URL to POST events to
    pub url: String,

    /// Event types to notify
    pub events: Vec<String>,

    /// Filter rules
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<FilterRules>,

    /// HTTP headers to include (e.g., Authorization)
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,

    /// Secret for HMAC signature (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Timeout in seconds
    #[serde(default = "default_webhook_timeout")]
    pub timeout_secs: u64,

    /// Number of retries on failure
    #[serde(default = "default_webhook_retries")]
    pub max_retries: u32,
}

fn default_webhook_timeout() -> u64 {
    30
}

fn default_webhook_retries() -> u32 {
    3
}

impl NotificationTarget for WebhookConfiguration {
    fn id(&self) -> &str {
        &self.id
    }
    fn events(&self) -> &[String] {
        &self.events
    }
    fn filter(&self) -> Option<&FilterRules> {
        self.filter.as_ref()
    }
}

/// Compute HMAC signature for webhook payload
#[cfg(feature = "webhooks")]
fn compute_webhook_signature(secret: &str, payload: &str) -> String {
    use blake3::Hasher;

    // Use BLAKE3 keyed hash as HMAC
    let mut hasher = Hasher::new_keyed(secret.as_bytes().try_into().unwrap_or(&[0u8; 32]));
    hasher.update(payload.as_bytes());
    let hash = hasher.finalize();
    format!("blake3={}", hex::encode(hash.as_bytes()))
}

/// Filter rules for key-based filtering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRules {
    /// Key filter
    pub key: KeyFilter,
}

impl FilterRules {
    /// Check if key matches filter rules
    pub fn matches(&self, key: &str) -> bool {
        self.key.matches(key)
    }
}

/// Key filter with prefix and suffix rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFilter {
    /// Filter rules
    pub filter_rules: Vec<FilterRule>,
}

impl KeyFilter {
    /// Check if key matches filter rules
    pub fn matches(&self, key: &str) -> bool {
        for rule in &self.filter_rules {
            match rule.name.to_lowercase().as_str() {
                "prefix" => {
                    if !key.starts_with(&rule.value) {
                        return false;
                    }
                }
                "suffix" => {
                    if !key.ends_with(&rule.value) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        true
    }
}

/// A single filter rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    /// Rule name (Prefix or Suffix)
    pub name: String,

    /// Rule value
    pub value: String,
}

// =============================================================================
// Event Emitter
// =============================================================================

/// Configuration for the event emitter
#[derive(Debug, Clone)]
pub struct EventConfig {
    /// Enable event emission
    pub enabled: bool,

    /// Channel capacity for internal broadcast
    pub channel_capacity: usize,

    /// Enable integration with HPC-Channels
    pub hpc_channels_enabled: bool,

    /// Region name for events
    pub region: String,
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            channel_capacity: EVENT_CHANNEL_CAPACITY,
            // Enable HPC-Channels by default when the feature is enabled
            #[cfg(feature = "hpc-channels")]
            hpc_channels_enabled: true,
            #[cfg(not(feature = "hpc-channels"))]
            hpc_channels_enabled: false,
            region: "warp-local".to_string(),
        }
    }
}

/// Event emitter for broadcasting storage events
pub struct EventEmitter {
    /// Configuration
    config: EventConfig,

    /// Broadcast sender for local subscribers
    sender: broadcast::Sender<S3Event>,

    /// Notification configurations per bucket
    notifications: Arc<dashmap::DashMap<String, NotificationConfiguration>>,

    /// HPC-Channels broadcast sender (when feature is enabled)
    #[cfg(feature = "hpc-channels")]
    hpc_sender: tokio::sync::broadcast::Sender<StorageEventMessage>,

    /// HTTP client for webhooks (when feature is enabled)
    #[cfg(feature = "webhooks")]
    http_client: reqwest::Client,
}

impl EventEmitter {
    /// Create a new event emitter
    pub fn new(config: EventConfig) -> Self {
        let (sender, _) = broadcast::channel(config.channel_capacity);

        #[cfg(feature = "hpc-channels")]
        let hpc_sender = if config.hpc_channels_enabled {
            // Register with global HPC-Channels registry
            hpc_broadcast::<StorageEventMessage>(channels::STORAGE_EVENTS, config.channel_capacity)
        } else {
            // Create a dummy sender that won't be used
            let (tx, _) = tokio::sync::broadcast::channel(1);
            tx
        };

        #[cfg(feature = "webhooks")]
        let http_client = reqwest::Client::builder()
            .user_agent("warp-store/0.1")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            sender,
            notifications: Arc::new(dashmap::DashMap::new()),
            #[cfg(feature = "hpc-channels")]
            hpc_sender,
            #[cfg(feature = "webhooks")]
            http_client,
        }
    }

    /// Subscribe to all events (local broadcast channel)
    pub fn subscribe(&self) -> broadcast::Receiver<S3Event> {
        self.sender.subscribe()
    }

    /// Subscribe to HPC-Channels storage events
    ///
    /// This allows receiving events from the global HPC-Channels registry,
    /// which can include events from multiple warp-store instances.
    #[cfg(feature = "hpc-channels")]
    pub fn subscribe_hpc_channels(&self) -> tokio::sync::broadcast::Receiver<StorageEventMessage> {
        self.hpc_sender.subscribe()
    }

    /// Set notification configuration for a bucket
    pub fn set_notification_config(&self, bucket: &str, config: NotificationConfiguration) {
        self.notifications.insert(bucket.to_string(), config);
        info!(bucket = bucket, "Updated notification configuration");
    }

    /// Get notification configuration for a bucket
    pub fn get_notification_config(&self, bucket: &str) -> Option<NotificationConfiguration> {
        self.notifications.get(bucket).map(|r| r.value().clone())
    }

    /// Delete notification configuration for a bucket
    pub fn delete_notification_config(&self, bucket: &str) {
        self.notifications.remove(bucket);
        info!(bucket = bucket, "Deleted notification configuration");
    }

    /// Emit an event
    pub fn emit(&self, event: S3Event) {
        if !self.config.enabled {
            return;
        }

        let bucket = &event.s3.bucket.name;
        let key = &event.s3.object.key;

        debug!(
            event = event.event_name.as_str(),
            bucket = bucket,
            key = key,
            "Emitting storage event"
        );

        // Check bucket notification configuration
        if let Some(config) = self.notifications.get(bucket) {
            if config.matches_event(&event) {
                let destinations = config.get_destinations(&event);
                for dest in destinations {
                    self.send_to_destination(&event, dest);
                }
            }
        }

        // Always send to local broadcast channel
        if let Err(e) = self.sender.send(event.clone()) {
            debug!(error = ?e, "No active subscribers for event");
        }

        // Send to HPC-Channels if enabled
        if self.config.hpc_channels_enabled {
            self.send_to_hpc_channels(&event);
        }
    }

    /// Send event to a specific destination
    fn send_to_destination(&self, event: &S3Event, destination: EventDestination) {
        match destination {
            EventDestination::Topic(arn) => {
                debug!(arn = arn.as_str(), "Would send to SNS topic");
                // TODO: Implement SNS integration
            }
            EventDestination::Queue(arn) => {
                debug!(arn = arn.as_str(), "Would send to SQS queue");
                // TODO: Implement SQS integration
            }
            EventDestination::Lambda(arn) => {
                debug!(arn = arn.as_str(), "Would invoke Lambda function");
                // TODO: Implement Lambda integration
            }
            EventDestination::HpcChannel(channel_id) => {
                debug!(channel = channel_id.as_str(), "Would send to HPC channel");
                // TODO: Send to specific HPC-Channels channel
            }
            EventDestination::Webhook(config) => {
                self.send_to_webhook(event.clone(), config);
            }
        }
    }

    /// Send event to a webhook endpoint
    #[cfg(feature = "webhooks")]
    fn send_to_webhook(&self, event: S3Event, config: WebhookConfiguration) {
        let client = self.http_client.clone();

        // Spawn async task for webhook delivery
        tokio::spawn(async move {
            let url = &config.url;
            let timeout = std::time::Duration::from_secs(config.timeout_secs);
            let max_retries = config.max_retries;

            // Build request
            let mut request = client
                .post(url)
                .timeout(timeout)
                .header("Content-Type", "application/json");

            // Add custom headers
            for (key, value) in &config.headers {
                request = request.header(key, value);
            }

            // Add HMAC signature if secret is configured
            if let Some(secret) = &config.secret {
                if let Ok(body_json) = serde_json::to_string(&event) {
                    let signature = compute_webhook_signature(secret, &body_json);
                    request = request.header("X-Warp-Signature", signature);
                }
            }

            // Serialize event to JSON
            let body = match serde_json::to_string(&event) {
                Ok(json) => json,
                Err(e) => {
                    warn!(
                        url = url.as_str(),
                        error = %e,
                        "Failed to serialize event for webhook"
                    );
                    return;
                }
            };

            // Retry loop
            for attempt in 1..=max_retries {
                debug!(
                    url = url.as_str(),
                    attempt = attempt,
                    "Sending webhook"
                );

                match request.try_clone().unwrap().body(body.clone()).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            info!(
                                url = url.as_str(),
                                status = %response.status(),
                                "Webhook delivered successfully"
                            );
                            return;
                        } else {
                            warn!(
                                url = url.as_str(),
                                status = %response.status(),
                                attempt = attempt,
                                "Webhook returned non-success status"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(
                            url = url.as_str(),
                            error = %e,
                            attempt = attempt,
                            "Webhook delivery failed"
                        );
                    }
                }

                // Exponential backoff before retry
                if attempt < max_retries {
                    let backoff = std::time::Duration::from_millis(100 * 2u64.pow(attempt - 1));
                    tokio::time::sleep(backoff).await;
                }
            }

            warn!(
                url = url.as_str(),
                max_retries = max_retries,
                "Webhook delivery failed after all retries"
            );
        });
    }

    /// Stub for webhook sending when feature is disabled
    #[cfg(not(feature = "webhooks"))]
    fn send_to_webhook(&self, _event: S3Event, config: WebhookConfiguration) {
        debug!(
            url = config.url.as_str(),
            "Webhooks feature not enabled"
        );
    }

    /// Send event to HPC-Channels global broadcast
    #[cfg(feature = "hpc-channels")]
    fn send_to_hpc_channels(&self, event: &S3Event) {
        // Convert S3Event to StorageEventMessage for HPC-Channels
        let record = StorageEventRecord {
            event_version: event.event_version.clone(),
            event_source: event.event_source.clone(),
            aws_region: event.aws_region.clone(),
            event_time: event.event_time.to_rfc3339(),
            event_name: event.event_name.clone(),
            user_identity: StorageUserIdentity {
                principal_id: event.user_identity.principal_id.clone(),
            },
            bucket: StorageBucketInfo {
                name: event.s3.bucket.name.clone(),
                arn: event.s3.bucket.arn.clone(),
            },
            object: StorageObjectInfo {
                key: event.s3.object.key.clone(),
                size: event.s3.object.size,
                etag: event.s3.object.etag.clone(),
                version_id: event.s3.object.version_id.clone(),
                sequencer: event.s3.object.sequencer.clone(),
            },
        };

        let message = StorageEventMessage::from_record(record);

        // Broadcast to HPC-Channels
        match self.hpc_sender.send(message) {
            Ok(receivers) => {
                debug!(
                    channel = STORAGE_EVENTS_CHANNEL,
                    event = event.event_name.as_str(),
                    receivers = receivers,
                    "Broadcast to HPC-Channels"
                );
            }
            Err(e) => {
                debug!(
                    channel = STORAGE_EVENTS_CHANNEL,
                    event = event.event_name.as_str(),
                    error = ?e,
                    "No active HPC-Channels subscribers"
                );
            }
        }
    }

    /// Send event to HPC-Channels global broadcast (stub when feature disabled)
    #[cfg(not(feature = "hpc-channels"))]
    fn send_to_hpc_channels(&self, event: &S3Event) {
        debug!(
            channel = STORAGE_EVENTS_CHANNEL,
            event = event.event_name.as_str(),
            "HPC-Channels feature not enabled"
        );
    }

    /// Emit object created event
    pub fn emit_object_created(&self, key: &ObjectKey, size: u64, etag: &str) {
        let event = S3Event::object_created(key, size, etag);
        self.emit(event);
    }

    /// Emit object deleted event
    pub fn emit_object_deleted(&self, key: &ObjectKey) {
        let event = S3Event::object_deleted(key);
        self.emit(event);
    }

    /// Emit multipart upload completed event
    pub fn emit_multipart_completed(&self, key: &ObjectKey, size: u64, etag: &str) {
        let event = S3Event::multipart_completed(key, size, etag);
        self.emit(event);
    }

    /// Emit lifecycle expiration event
    pub fn emit_lifecycle_expired(&self, bucket: &str, key: &str) {
        let event = S3Event::lifecycle_expired(bucket, key);
        self.emit(event);
    }

    /// Emit lifecycle transition event
    pub fn emit_lifecycle_transitioned(
        &self,
        bucket: &str,
        key: &str,
        size: u64,
        target_storage_class: &str,
    ) {
        let event = S3Event::lifecycle_transitioned(bucket, key, size, target_storage_class);
        self.emit(event);
    }

    /// Get statistics about event emission
    pub fn stats(&self) -> EventStats {
        EventStats {
            subscribers: self.sender.receiver_count(),
            buckets_configured: self.notifications.len(),
        }
    }
}

/// Event emission statistics
#[derive(Debug, Clone)]
pub struct EventStats {
    /// Number of active subscribers
    pub subscribers: usize,

    /// Number of buckets with notification configuration
    pub buckets_configured: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_matching() {
        assert!(EventType::ObjectCreatedPut.matches("s3:ObjectCreated:Put"));
        assert!(EventType::ObjectCreatedPut.matches("s3:ObjectCreated:*"));
        assert!(EventType::ObjectCreatedPut.matches("s3:*"));
        assert!(!EventType::ObjectCreatedPut.matches("s3:ObjectRemoved:*"));
    }

    #[test]
    fn test_filter_rules() {
        let filter = FilterRules {
            key: KeyFilter {
                filter_rules: vec![
                    FilterRule {
                        name: "Prefix".to_string(),
                        value: "logs/".to_string(),
                    },
                    FilterRule {
                        name: "Suffix".to_string(),
                        value: ".json".to_string(),
                    },
                ],
            },
        };

        assert!(filter.matches("logs/app.json"));
        assert!(!filter.matches("logs/app.txt"));
        assert!(!filter.matches("data/app.json"));
    }

    #[test]
    fn test_s3_event_creation() {
        let key = ObjectKey::new("test-bucket", "path/to/file.txt").unwrap();
        let event = S3Event::object_created(&key, 1024, "\"abc123\"");

        assert_eq!(event.event_name, "s3:ObjectCreated:Put");
        assert_eq!(event.s3.bucket.name, "test-bucket");
        assert_eq!(event.s3.object.key, "path/to/file.txt");
        assert_eq!(event.s3.object.size, 1024);
    }

    #[test]
    fn test_event_emitter() {
        let emitter = EventEmitter::new(EventConfig::default());
        let mut rx = emitter.subscribe();

        let key = ObjectKey::new("bucket", "key").unwrap();
        emitter.emit_object_created(&key, 100, "etag");

        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_name, "s3:ObjectCreated:Put");
    }

    #[test]
    fn test_notification_configuration() {
        let emitter = EventEmitter::new(EventConfig::default());

        let config = NotificationConfiguration {
            hpc_channel_configurations: vec![HpcChannelConfiguration {
                id: "test".to_string(),
                channel_id: "hpc.storage.events".to_string(),
                events: vec!["s3:ObjectCreated:*".to_string()],
                filter: Some(FilterRules {
                    key: KeyFilter {
                        filter_rules: vec![FilterRule {
                            name: "Prefix".to_string(),
                            value: "uploads/".to_string(),
                        }],
                    },
                }),
            }],
            ..Default::default()
        };

        emitter.set_notification_config("test-bucket", config);

        let retrieved = emitter.get_notification_config("test-bucket").unwrap();
        assert_eq!(retrieved.hpc_channel_configurations.len(), 1);
        assert_eq!(
            retrieved.hpc_channel_configurations[0].channel_id,
            "hpc.storage.events"
        );
    }

    #[cfg(feature = "hpc-channels")]
    #[test]
    fn test_hpc_channels_event_publishing() {
        let config = EventConfig {
            enabled: true,
            channel_capacity: 16,
            hpc_channels_enabled: true,
            region: "test-region".to_string(),
        };
        let emitter = EventEmitter::new(config);
        let mut hpc_rx = emitter.subscribe_hpc_channels();

        // Emit an event
        let key = ObjectKey::new("test-bucket", "test-key.txt").unwrap();
        emitter.emit_object_created(&key, 1024, "\"test-etag\"");

        // Check that the event was received via HPC-Channels
        let message = hpc_rx.try_recv().unwrap();
        assert_eq!(message.records.len(), 1);

        let record = &message.records[0];
        assert_eq!(record.event_name, "s3:ObjectCreated:Put");
        assert_eq!(record.bucket.name, "test-bucket");
        assert_eq!(record.object.key, "test-key.txt");
        assert_eq!(record.object.size, 1024);
        assert_eq!(record.object.etag, "\"test-etag\"");
    }

    #[cfg(feature = "hpc-channels")]
    #[test]
    fn test_hpc_channels_disabled() {
        let config = EventConfig {
            enabled: true,
            channel_capacity: 16,
            hpc_channels_enabled: false, // HPC-Channels disabled
            region: "test-region".to_string(),
        };
        let emitter = EventEmitter::new(config);
        let mut hpc_rx = emitter.subscribe_hpc_channels();

        // Emit an event - should NOT be sent to HPC-Channels
        let key = ObjectKey::new("test-bucket", "test-key.txt").unwrap();
        emitter.emit_object_created(&key, 1024, "\"test-etag\"");

        // Should not receive anything (hpc_channels_enabled is false)
        assert!(hpc_rx.try_recv().is_err());
    }
}
