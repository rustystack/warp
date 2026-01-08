//! AWS Event Destinations
//!
//! Implements SNS, SQS, and Lambda event destinations for S3-compatible event notifications.
//! These integrations allow WARP storage events to be published to AWS services for
//! downstream processing.
//!
//! # Supported Destinations
//!
//! - **SNS Topics**: Publish events to SNS topics for fan-out to multiple subscribers
//! - **SQS Queues**: Send events to SQS queues for reliable message processing
//! - **Lambda Functions**: Invoke Lambda functions synchronously or asynchronously
//!
//! # Configuration
//!
//! Each destination requires proper IAM credentials configured via environment variables
//! or the AWS credentials provider chain.
//!
//! # Feature Flag
//!
//! This module requires the `aws-events` feature to be enabled.

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::S3Event;

/// Result type for AWS destination operations
pub type AwsEventResult<T> = Result<T, AwsEventError>;

/// Errors from AWS event destinations
#[derive(Debug, thiserror::Error)]
pub enum AwsEventError {
    /// SNS publish failed
    #[error("SNS publish failed: {0}")]
    SnsPublishFailed(String),

    /// SQS send failed
    #[error("SQS send failed: {0}")]
    SqsSendFailed(String),

    /// Lambda invocation failed
    #[error("Lambda invocation failed: {0}")]
    LambdaInvokeFailed(String),

    /// ARN parse error
    #[error("Invalid ARN format: {0}")]
    InvalidArn(String),

    /// AWS SDK error
    #[error("AWS SDK error: {0}")]
    SdkError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Configuration for AWS event destinations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AwsEventConfig {
    /// AWS region override (uses default if not set)
    pub region: Option<String>,

    /// SNS topic configuration
    pub sns_config: Option<SnsConfig>,

    /// SQS queue configuration
    pub sqs_config: Option<SqsConfig>,

    /// Lambda function configuration
    pub lambda_config: Option<LambdaConfig>,
}

/// SNS-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnsConfig {
    /// Maximum retries for publish operations
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Timeout for publish operations in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for SnsConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            timeout_ms: default_timeout_ms(),
        }
    }
}

/// SQS-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqsConfig {
    /// Maximum retries for send operations
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Timeout for send operations in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Message delay in seconds (0-900)
    #[serde(default)]
    pub delay_seconds: i32,
}

impl Default for SqsConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            timeout_ms: default_timeout_ms(),
            delay_seconds: 0,
        }
    }
}

/// Lambda-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaConfig {
    /// Maximum retries for invocation
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Timeout for invocation in milliseconds
    #[serde(default = "default_lambda_timeout_ms")]
    pub timeout_ms: u64,

    /// Invocation type (sync or async)
    #[serde(default)]
    pub invocation_type: LambdaInvocationType,
}

impl Default for LambdaConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            timeout_ms: default_lambda_timeout_ms(),
            invocation_type: LambdaInvocationType::Event,
        }
    }
}

/// Lambda invocation type
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum LambdaInvocationType {
    /// Asynchronous invocation (fire and forget)
    #[default]
    Event,
    /// Synchronous invocation (wait for response)
    RequestResponse,
    /// Dry run (validate only)
    DryRun,
}

/// Default maximum retry attempts for AWS operations.
fn default_max_retries() -> u32 {
    3
}

/// Default timeout in milliseconds for SNS and SQS operations.
fn default_timeout_ms() -> u64 {
    5000
}

/// Default timeout in milliseconds for Lambda invocations.
fn default_lambda_timeout_ms() -> u64 {
    30000
}

// =============================================================================
// AWS SDK Implementation (when feature is enabled)
// =============================================================================

#[cfg(feature = "aws-events")]
mod aws_impl {
    use super::*;
    use aws_sdk_lambda::Client as LambdaClient;
    use aws_sdk_lambda::primitives::Blob;
    use aws_sdk_sns::Client as SnsClient;
    use aws_sdk_sqs::Client as SqsClient;

    /// AWS event destination clients.
    pub struct AwsEventClients {
        /// SNS client for publishing to topics.
        sns: Option<SnsClient>,
        /// SQS client for sending to queues.
        sqs: Option<SqsClient>,
        /// Lambda client for function invocations.
        lambda: Option<LambdaClient>,
        /// Configuration for AWS event destinations.
        config: AwsEventConfig,
    }

    impl AwsEventClients {
        /// Create new AWS clients from configuration
        pub async fn new(config: AwsEventConfig) -> AwsEventResult<Self> {
            let sdk_config = if let Some(region) = &config.region {
                aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new(region.clone()))
                    .load()
                    .await
            } else {
                aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await
            };

            let sns = if config.sns_config.is_some() {
                Some(SnsClient::new(&sdk_config))
            } else {
                None
            };

            let sqs = if config.sqs_config.is_some() {
                Some(SqsClient::new(&sdk_config))
            } else {
                None
            };

            let lambda = if config.lambda_config.is_some() {
                Some(LambdaClient::new(&sdk_config))
            } else {
                None
            };

            info!(
                sns_enabled = sns.is_some(),
                sqs_enabled = sqs.is_some(),
                lambda_enabled = lambda.is_some(),
                "AWS event clients initialized"
            );

            Ok(Self {
                sns,
                sqs,
                lambda,
                config,
            })
        }

        /// Publish event to SNS topic
        pub async fn publish_to_sns(
            &self,
            topic_arn: &str,
            event: &S3Event,
        ) -> AwsEventResult<String> {
            let client = self.sns.as_ref().ok_or_else(|| {
                AwsEventError::ConfigError("SNS client not configured".to_string())
            })?;

            let message = S3EventMessage::from_event(event.clone());
            let message_json = serde_json::to_string(&message)
                .map_err(|e| AwsEventError::SerializationError(e.to_string()))?;

            let sns_config = self
                .config
                .sns_config
                .as_ref()
                .unwrap_or(&SnsConfig::default());
            let mut last_error = None;

            for attempt in 1..=sns_config.max_retries {
                debug!(
                    topic = topic_arn,
                    attempt = attempt,
                    event = event.event_name.as_str(),
                    "Publishing to SNS"
                );

                match client
                    .publish()
                    .topic_arn(topic_arn)
                    .message(&message_json)
                    .message_attributes(
                        "eventType",
                        aws_sdk_sns::types::MessageAttributeValue::builder()
                            .data_type("String")
                            .string_value(&event.event_name)
                            .build()
                            .map_err(|e| AwsEventError::SdkError(e.to_string()))?,
                    )
                    .message_attributes(
                        "bucket",
                        aws_sdk_sns::types::MessageAttributeValue::builder()
                            .data_type("String")
                            .string_value(&event.s3.bucket.name)
                            .build()
                            .map_err(|e| AwsEventError::SdkError(e.to_string()))?,
                    )
                    .send()
                    .await
                {
                    Ok(output) => {
                        let message_id = output.message_id().unwrap_or("unknown").to_string();
                        info!(
                            topic = topic_arn,
                            message_id = message_id.as_str(),
                            event = event.event_name.as_str(),
                            "Published to SNS"
                        );
                        return Ok(message_id);
                    }
                    Err(e) => {
                        warn!(
                            topic = topic_arn,
                            attempt = attempt,
                            error = %e,
                            "SNS publish attempt failed"
                        );
                        last_error = Some(e.to_string());

                        if attempt < sns_config.max_retries {
                            let backoff = Duration::from_millis(100 * 2u64.pow(attempt - 1));
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            }

            Err(AwsEventError::SnsPublishFailed(
                last_error.unwrap_or_else(|| "Unknown error".to_string()),
            ))
        }

        /// Send event to SQS queue
        pub async fn send_to_sqs(
            &self,
            queue_url: &str,
            event: &S3Event,
        ) -> AwsEventResult<String> {
            let client = self.sqs.as_ref().ok_or_else(|| {
                AwsEventError::ConfigError("SQS client not configured".to_string())
            })?;

            let message = S3EventMessage::from_event(event.clone());
            let message_json = serde_json::to_string(&message)
                .map_err(|e| AwsEventError::SerializationError(e.to_string()))?;

            let sqs_config = self
                .config
                .sqs_config
                .as_ref()
                .unwrap_or(&SqsConfig::default());
            let mut last_error = None;

            for attempt in 1..=sqs_config.max_retries {
                debug!(
                    queue = queue_url,
                    attempt = attempt,
                    event = event.event_name.as_str(),
                    "Sending to SQS"
                );

                match client
                    .send_message()
                    .queue_url(queue_url)
                    .message_body(&message_json)
                    .delay_seconds(sqs_config.delay_seconds)
                    .message_attributes(
                        "eventType",
                        aws_sdk_sqs::types::MessageAttributeValue::builder()
                            .data_type("String")
                            .string_value(&event.event_name)
                            .build()
                            .map_err(|e| AwsEventError::SdkError(e.to_string()))?,
                    )
                    .message_attributes(
                        "bucket",
                        aws_sdk_sqs::types::MessageAttributeValue::builder()
                            .data_type("String")
                            .string_value(&event.s3.bucket.name)
                            .build()
                            .map_err(|e| AwsEventError::SdkError(e.to_string()))?,
                    )
                    .send()
                    .await
                {
                    Ok(output) => {
                        let message_id = output.message_id().unwrap_or("unknown").to_string();
                        info!(
                            queue = queue_url,
                            message_id = message_id.as_str(),
                            event = event.event_name.as_str(),
                            "Sent to SQS"
                        );
                        return Ok(message_id);
                    }
                    Err(e) => {
                        warn!(
                            queue = queue_url,
                            attempt = attempt,
                            error = %e,
                            "SQS send attempt failed"
                        );
                        last_error = Some(e.to_string());

                        if attempt < sqs_config.max_retries {
                            let backoff = Duration::from_millis(100 * 2u64.pow(attempt - 1));
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            }

            Err(AwsEventError::SqsSendFailed(
                last_error.unwrap_or_else(|| "Unknown error".to_string()),
            ))
        }

        /// Invoke Lambda function with event
        pub async fn invoke_lambda(
            &self,
            function_arn: &str,
            event: &S3Event,
        ) -> AwsEventResult<Option<Vec<u8>>> {
            let client = self.lambda.as_ref().ok_or_else(|| {
                AwsEventError::ConfigError("Lambda client not configured".to_string())
            })?;

            let message = S3EventMessage::from_event(event.clone());
            let payload = serde_json::to_vec(&message)
                .map_err(|e| AwsEventError::SerializationError(e.to_string()))?;

            let lambda_config = self
                .config
                .lambda_config
                .as_ref()
                .unwrap_or(&LambdaConfig::default());
            let mut last_error = None;

            let invocation_type = match lambda_config.invocation_type {
                LambdaInvocationType::Event => aws_sdk_lambda::types::InvocationType::Event,
                LambdaInvocationType::RequestResponse => {
                    aws_sdk_lambda::types::InvocationType::RequestResponse
                }
                LambdaInvocationType::DryRun => aws_sdk_lambda::types::InvocationType::DryRun,
            };

            for attempt in 1..=lambda_config.max_retries {
                debug!(
                    function = function_arn,
                    attempt = attempt,
                    event = event.event_name.as_str(),
                    invocation_type = ?lambda_config.invocation_type,
                    "Invoking Lambda"
                );

                match client
                    .invoke()
                    .function_name(function_arn)
                    .invocation_type(invocation_type.clone())
                    .payload(Blob::new(payload.clone()))
                    .send()
                    .await
                {
                    Ok(output) => {
                        let status_code = output.status_code().unwrap_or(0);

                        // Check for function error
                        if let Some(error) = output.function_error() {
                            warn!(
                                function = function_arn,
                                error = error,
                                "Lambda function returned error"
                            );
                            return Err(AwsEventError::LambdaInvokeFailed(error.to_string()));
                        }

                        info!(
                            function = function_arn,
                            status_code = status_code,
                            event = event.event_name.as_str(),
                            "Lambda invoked successfully"
                        );

                        // Return payload for RequestResponse
                        let response_payload = output.payload().map(|p| p.as_ref().to_vec());
                        return Ok(response_payload);
                    }
                    Err(e) => {
                        warn!(
                            function = function_arn,
                            attempt = attempt,
                            error = %e,
                            "Lambda invocation attempt failed"
                        );
                        last_error = Some(e.to_string());

                        if attempt < lambda_config.max_retries {
                            let backoff = Duration::from_millis(100 * 2u64.pow(attempt - 1));
                            tokio::time::sleep(backoff).await;
                        }
                    }
                }
            }

            Err(AwsEventError::LambdaInvokeFailed(
                last_error.unwrap_or_else(|| "Unknown error".to_string()),
            ))
        }

        /// Get queue URL from ARN
        pub async fn get_queue_url_from_arn(&self, queue_arn: &str) -> AwsEventResult<String> {
            // Parse ARN format: arn:aws:sqs:region:account:queue-name
            let parts: Vec<&str> = queue_arn.split(':').collect();
            if parts.len() != 6 || parts[2] != "sqs" {
                return Err(AwsEventError::InvalidArn(format!(
                    "Invalid SQS ARN format: {}",
                    queue_arn
                )));
            }

            let region = parts[3];
            let account_id = parts[4];
            let queue_name = parts[5];

            // Construct queue URL
            Ok(format!(
                "https://sqs.{}.amazonaws.com/{}/{}",
                region, account_id, queue_name
            ))
        }
    }

    /// Statistics for AWS event delivery
    #[derive(Debug, Clone, Default)]
    pub struct AwsEventStats {
        /// SNS messages published
        pub sns_published: u64,
        /// SNS publish failures
        pub sns_failures: u64,
        /// SQS messages sent
        pub sqs_sent: u64,
        /// SQS send failures
        pub sqs_failures: u64,
        /// Lambda invocations
        pub lambda_invocations: u64,
        /// Lambda failures
        pub lambda_failures: u64,
    }
}

#[cfg(feature = "aws-events")]
pub use aws_impl::*;

// =============================================================================
// Stub implementation (when feature is disabled)
// =============================================================================

#[cfg(not(feature = "aws-events"))]
mod stub_impl {
    use super::*;

    /// Stub AWS event clients (when feature is disabled).
    pub struct AwsEventClients {
        /// Configuration for AWS event destinations.
        config: AwsEventConfig,
    }

    impl AwsEventClients {
        /// Create stub clients
        pub async fn new(config: AwsEventConfig) -> AwsEventResult<Self> {
            warn!("AWS events feature not enabled - destinations will not be delivered");
            Ok(Self { config })
        }

        /// Stub SNS publish
        pub async fn publish_to_sns(
            &self,
            topic_arn: &str,
            _event: &S3Event,
        ) -> AwsEventResult<String> {
            warn!(
                topic = topic_arn,
                "AWS events feature not enabled - SNS publish skipped"
            );
            Ok("stub-message-id".to_string())
        }

        /// Stub SQS send
        pub async fn send_to_sqs(
            &self,
            queue_url: &str,
            _event: &S3Event,
        ) -> AwsEventResult<String> {
            warn!(
                queue = queue_url,
                "AWS events feature not enabled - SQS send skipped"
            );
            Ok("stub-message-id".to_string())
        }

        /// Stub Lambda invoke
        pub async fn invoke_lambda(
            &self,
            function_arn: &str,
            _event: &S3Event,
        ) -> AwsEventResult<Option<Vec<u8>>> {
            warn!(
                function = function_arn,
                "AWS events feature not enabled - Lambda invoke skipped"
            );
            Ok(None)
        }

        /// Get queue URL from ARN (stub)
        pub async fn get_queue_url_from_arn(&self, queue_arn: &str) -> AwsEventResult<String> {
            let parts: Vec<&str> = queue_arn.split(':').collect();
            if parts.len() != 6 || parts[2] != "sqs" {
                return Err(AwsEventError::InvalidArn(format!(
                    "Invalid SQS ARN format: {}",
                    queue_arn
                )));
            }

            let region = parts[3];
            let account_id = parts[4];
            let queue_name = parts[5];

            Ok(format!(
                "https://sqs.{}.amazonaws.com/{}/{}",
                region, account_id, queue_name
            ))
        }
    }

    /// Stub statistics for AWS event delivery (when feature is disabled).
    #[derive(Debug, Clone, Default)]
    pub struct AwsEventStats {
        /// SNS messages published.
        pub sns_published: u64,
        /// SNS publish failures.
        pub sns_failures: u64,
        /// SQS messages sent.
        pub sqs_sent: u64,
        /// SQS send failures.
        pub sqs_failures: u64,
        /// Lambda invocations.
        pub lambda_invocations: u64,
        /// Lambda failures.
        pub lambda_failures: u64,
    }
}

#[cfg(not(feature = "aws-events"))]
pub use stub_impl::*;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObjectKey;

    fn create_test_event() -> S3Event {
        let key = ObjectKey::new("test-bucket", "test/key.txt").unwrap();
        S3Event::object_created(&key, 1024, "\"etag123\"")
    }

    #[test]
    fn test_aws_event_config_default() {
        let config = AwsEventConfig::default();
        assert!(config.region.is_none());
        assert!(config.sns_config.is_none());
        assert!(config.sqs_config.is_none());
        assert!(config.lambda_config.is_none());
    }

    #[test]
    fn test_sns_config_default() {
        let config = SnsConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn test_sqs_config_default() {
        let config = SqsConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.timeout_ms, 5000);
        assert_eq!(config.delay_seconds, 0);
    }

    #[test]
    fn test_lambda_config_default() {
        let config = LambdaConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.timeout_ms, 30000);
        assert_eq!(config.invocation_type, LambdaInvocationType::Event);
    }

    #[test]
    fn test_lambda_invocation_type_default() {
        let inv_type = LambdaInvocationType::default();
        assert_eq!(inv_type, LambdaInvocationType::Event);
    }

    #[tokio::test]
    async fn test_aws_clients_creation() {
        let config = AwsEventConfig::default();
        let clients = AwsEventClients::new(config).await.unwrap();

        // In stub mode, this should succeed
        let event = create_test_event();
        let result = clients
            .publish_to_sns("arn:aws:sns:us-east-1:123456789:test", &event)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_queue_url_from_arn() {
        let config = AwsEventConfig::default();
        let clients = AwsEventClients::new(config).await.unwrap();

        let url = clients
            .get_queue_url_from_arn("arn:aws:sqs:us-east-1:123456789012:my-queue")
            .await
            .unwrap();

        assert_eq!(
            url,
            "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue"
        );
    }

    #[tokio::test]
    async fn test_invalid_queue_arn() {
        let config = AwsEventConfig::default();
        let clients = AwsEventClients::new(config).await.unwrap();

        let result = clients.get_queue_url_from_arn("invalid-arn").await;
        assert!(matches!(result, Err(AwsEventError::InvalidArn(_))));
    }

    #[tokio::test]
    async fn test_sqs_send_stub() {
        let config = AwsEventConfig::default();
        let clients = AwsEventClients::new(config).await.unwrap();

        let event = create_test_event();
        let result = clients
            .send_to_sqs(
                "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue",
                &event,
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_lambda_invoke_stub() {
        let config = AwsEventConfig::default();
        let clients = AwsEventClients::new(config).await.unwrap();

        let event = create_test_event();
        let result = clients
            .invoke_lambda(
                "arn:aws:lambda:us-east-1:123456789012:function:test-function",
                &event,
            )
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Stub returns None
    }

    #[test]
    fn test_aws_event_stats_default() {
        let stats = AwsEventStats::default();
        assert_eq!(stats.sns_published, 0);
        assert_eq!(stats.sns_failures, 0);
        assert_eq!(stats.sqs_sent, 0);
        assert_eq!(stats.sqs_failures, 0);
        assert_eq!(stats.lambda_invocations, 0);
        assert_eq!(stats.lambda_failures, 0);
    }

    #[test]
    fn test_config_serialization() {
        let config = AwsEventConfig {
            region: Some("us-west-2".to_string()),
            sns_config: Some(SnsConfig {
                max_retries: 5,
                timeout_ms: 10000,
            }),
            sqs_config: Some(SqsConfig {
                max_retries: 3,
                timeout_ms: 5000,
                delay_seconds: 10,
            }),
            lambda_config: Some(LambdaConfig {
                max_retries: 2,
                timeout_ms: 60000,
                invocation_type: LambdaInvocationType::RequestResponse,
            }),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: AwsEventConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.region, Some("us-west-2".to_string()));
        assert_eq!(deserialized.sns_config.unwrap().max_retries, 5);
        assert_eq!(deserialized.sqs_config.unwrap().delay_seconds, 10);
        assert_eq!(
            deserialized.lambda_config.unwrap().invocation_type,
            LambdaInvocationType::RequestResponse
        );
    }
}
