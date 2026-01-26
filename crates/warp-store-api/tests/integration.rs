//! End-to-end integration tests for warp-store-api
//!
//! These tests spin up an actual HTTP server and test the full API flow.

#![allow(unused_imports)]

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::Client;
use tokio::net::TcpListener;
use tokio::time::timeout;

use warp_store::{Store, StoreConfig};
use warp_store_api::{ApiConfig, ApiServer};

/// Test server helper
struct TestServer {
    addr: SocketAddr,
    client: Client,
    _temp_dir: tempfile::TempDir,
}

impl TestServer {
    async fn new() -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let store_config = StoreConfig {
            root_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = Store::new(store_config).await.unwrap();

        // Find an available port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let api_config = ApiConfig {
            bind_addr: addr,
            enable_s3: true,
            enable_native: true,
            ..Default::default()
        };

        let server = ApiServer::new(store, api_config).await;
        let router = server.router();

        // Spawn the server in the background
        let listener = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        // Wait for server to be ready
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        Self {
            addr,
            client,
            _temp_dir: temp_dir,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

// =============================================================================
// Health Check Tests
// =============================================================================

#[tokio::test]
async fn test_health_check() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "OK");
}

// =============================================================================
// S3 Bucket Operations
// =============================================================================

#[tokio::test]
async fn test_s3_list_buckets_empty() {
    let server = TestServer::new().await;

    let resp = server.client.get(server.url("/")).send().await.unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<ListAllMyBucketsResult>"));
    assert!(body.contains("<Buckets>"));
}

#[tokio::test]
async fn test_s3_create_bucket() {
    let server = TestServer::new().await;

    // Create bucket
    let resp = server
        .client
        .put(server.url("/test-bucket"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Verify bucket exists in listing
    let resp = server.client.get(server.url("/")).send().await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(body.contains("test-bucket"));
}

#[tokio::test]
async fn test_s3_delete_bucket() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/delete-me"))
        .send()
        .await
        .unwrap();

    // Delete bucket
    let resp = server
        .client
        .delete(server.url("/delete-me"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);

    // Verify bucket no longer in listing
    let resp = server.client.get(server.url("/")).send().await.unwrap();
    let body = resp.text().await.unwrap();
    assert!(!body.contains("delete-me"));
}

// =============================================================================
// S3 Object Operations
// =============================================================================

#[tokio::test]
async fn test_s3_put_get_object() {
    let server = TestServer::new().await;

    // Create bucket first
    server
        .client
        .put(server.url("/objects"))
        .send()
        .await
        .unwrap();

    // Put object
    let data = b"Hello, warp-store!";
    let resp = server
        .client
        .put(server.url("/objects/hello.txt"))
        .body(data.to_vec())
        .header("Content-Type", "text/plain")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("etag"));

    // Get object
    let resp = server
        .client
        .get(server.url("/objects/hello.txt"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), data);
}

#[tokio::test]
async fn test_s3_head_object() {
    let server = TestServer::new().await;

    // Create bucket and object
    server
        .client
        .put(server.url("/head-test"))
        .send()
        .await
        .unwrap();

    let data = b"Test data for head";
    server
        .client
        .put(server.url("/head-test/file.bin"))
        .body(data.to_vec())
        .send()
        .await
        .unwrap();

    // Head object
    let resp = server
        .client
        .head(server.url("/head-test/file.bin"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("content-length"));
    assert!(resp.headers().contains_key("etag"));
}

#[tokio::test]
async fn test_s3_delete_object() {
    let server = TestServer::new().await;

    // Create bucket and object
    server
        .client
        .put(server.url("/del-obj"))
        .send()
        .await
        .unwrap();

    server
        .client
        .put(server.url("/del-obj/to-delete.txt"))
        .body("delete me")
        .send()
        .await
        .unwrap();

    // Delete object
    let resp = server
        .client
        .delete(server.url("/del-obj/to-delete.txt"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);

    // Verify object is gone
    let resp = server
        .client
        .get(server.url("/del-obj/to-delete.txt"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_s3_list_objects() {
    let server = TestServer::new().await;

    // Create bucket with multiple objects
    server
        .client
        .put(server.url("/list-test"))
        .send()
        .await
        .unwrap();

    for i in 0..5 {
        server
            .client
            .put(server.url(&format!("/list-test/file{}.txt", i)))
            .body(format!("content {}", i))
            .send()
            .await
            .unwrap();
    }

    // List objects
    let resp = server
        .client
        .get(server.url("/list-test"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<ListBucketResult>"));
    assert!(body.contains("file0.txt"));
    assert!(body.contains("file4.txt"));
}

#[tokio::test]
async fn test_s3_list_objects_with_prefix() {
    let server = TestServer::new().await;

    // Create bucket with objects in subdirectories
    server
        .client
        .put(server.url("/prefix-test"))
        .send()
        .await
        .unwrap();

    for path in ["dir1/a.txt", "dir1/b.txt", "dir2/c.txt", "root.txt"] {
        server
            .client
            .put(server.url(&format!("/prefix-test/{}", path)))
            .body("content")
            .send()
            .await
            .unwrap();
    }

    // List with prefix
    let resp = server
        .client
        .get(server.url("/prefix-test?prefix=dir1/"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("dir1/a.txt"));
    assert!(body.contains("dir1/b.txt"));
    assert!(!body.contains("dir2/c.txt"));
    assert!(!body.contains("root.txt"));
}

// =============================================================================
// Native API Tests
// =============================================================================

#[tokio::test]
async fn test_native_stats() {
    let server = TestServer::new().await;

    // Create some buckets
    server
        .client
        .put(server.url("/bucket1"))
        .send()
        .await
        .unwrap();
    server
        .client
        .put(server.url("/bucket2"))
        .send()
        .await
        .unwrap();

    // Get stats
    let resp = server
        .client
        .get(server.url("/api/v1/stats"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["buckets"], 2);
}

#[tokio::test]
async fn test_native_ephemeral_token() {
    let server = TestServer::new().await;

    // Create bucket and object
    server
        .client
        .put(server.url("/ephemeral"))
        .send()
        .await
        .unwrap();
    server
        .client
        .put(server.url("/ephemeral/secret.bin"))
        .body("secret data")
        .send()
        .await
        .unwrap();

    // Create ephemeral token
    let resp = server
        .client
        .post(server.url("/api/v1/ephemeral"))
        .json(&serde_json::json!({
            "bucket": "ephemeral",
            "key": "secret.bin",
            "ttl_seconds": 3600
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["token"].is_string());
    assert!(body["expires_at"].is_string());
    assert!(body["url"].is_string());

    // Verify token
    let token = body["token"].as_str().unwrap();
    let verify_resp = server
        .client
        .post(server.url("/api/v1/ephemeral/verify"))
        .json(&serde_json::json!({
            "token": token
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(verify_resp.status(), 200);
    let verify_body: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_body["valid"], true);
}

#[tokio::test]
async fn test_native_ephemeral_access() {
    let server = TestServer::new().await;

    // Create bucket and object
    server
        .client
        .put(server.url("/access-test"))
        .send()
        .await
        .unwrap();
    let content = "This is protected content";
    server
        .client
        .put(server.url("/access-test/protected.txt"))
        .body(content)
        .send()
        .await
        .unwrap();

    // Create ephemeral token with bucket scope (allows any key in bucket)
    let resp = server
        .client
        .post(server.url("/api/v1/ephemeral"))
        .json(&serde_json::json!({
            "bucket": "access-test",
            "key": "",
            "ttl_seconds": 3600,
            "scope": "bucket",
            "permissions": {
                "read": true,
                "write": false,
                "delete": false,
                "list": false
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["token"].as_str().unwrap();

    // Access via ephemeral URL with the key in path
    let access_url = format!("/api/v1/access/{}/protected.txt", token);
    let resp = server
        .client
        .get(server.url(&access_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), content);
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[tokio::test]
async fn test_get_nonexistent_object() {
    let server = TestServer::new().await;

    server
        .client
        .put(server.url("/errors"))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .get(server.url("/errors/does-not-exist.txt"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_nonexistent_bucket() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .delete(server.url("/nonexistent-bucket"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

// =============================================================================
// Large Object Tests
// =============================================================================

#[tokio::test]
async fn test_large_object() {
    let server = TestServer::new().await;

    server
        .client
        .put(server.url("/large"))
        .send()
        .await
        .unwrap();

    // Create 1MB object
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    let resp = server
        .client
        .put(server.url("/large/big-file.bin"))
        .body(data.clone())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Retrieve and verify
    let resp = server
        .client
        .get(server.url("/large/big-file.bin"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let received = resp.bytes().await.unwrap();
    assert_eq!(received.len(), data.len());
    assert_eq!(received.as_ref(), data.as_slice());
}

// =============================================================================
// Multipart Upload Tests
// =============================================================================

#[tokio::test]
async fn test_s3_multipart_upload() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/multipart"))
        .send()
        .await
        .unwrap();

    // 1. Create multipart upload
    let resp = server
        .client
        .post(server.url("/multipart/large-file.bin?uploads"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<InitiateMultipartUploadResult>"));
    assert!(body.contains("<UploadId>"));

    // Extract upload ID from XML
    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap();

    // 2. Upload parts
    let part1_data = b"Part 1 data ".to_vec();
    let resp = server
        .client
        .put(server.url(&format!(
            "/multipart/large-file.bin?uploadId={}&partNumber=1",
            upload_id
        )))
        .body(part1_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("etag"));

    let part2_data = b"Part 2 data".to_vec();
    let resp = server
        .client
        .put(server.url(&format!(
            "/multipart/large-file.bin?uploadId={}&partNumber=2",
            upload_id
        )))
        .body(part2_data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 3. Complete multipart upload
    let resp = server
        .client
        .post(server.url(&format!("/multipart/large-file.bin?uploadId={}", upload_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("<CompleteMultipartUploadResult>"));

    // 4. Verify final object
    let resp = server
        .client
        .get(server.url("/multipart/large-file.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let data = resp.bytes().await.unwrap();
    let expected: Vec<u8> = [part1_data, part2_data].concat();
    assert_eq!(data.as_ref(), expected.as_slice());
}

#[tokio::test]
async fn test_s3_multipart_upload_abort() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/abort-test"))
        .send()
        .await
        .unwrap();

    // Create multipart upload
    let resp = server
        .client
        .post(server.url("/abort-test/to-abort.bin?uploads"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    let upload_id = body
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap();

    // Upload a part
    server
        .client
        .put(server.url(&format!(
            "/abort-test/to-abort.bin?uploadId={}&partNumber=1",
            upload_id
        )))
        .body("some data")
        .send()
        .await
        .unwrap();

    // Abort the upload
    let resp = server
        .client
        .delete(server.url(&format!("/abort-test/to-abort.bin?uploadId={}", upload_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Object should not exist
    let resp = server
        .client
        .get(server.url("/abort-test/to-abort.bin"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// =============================================================================
// S3 Select Tests
// =============================================================================

#[cfg(feature = "s3-select")]
#[tokio::test]
async fn test_s3_select_json_simple() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/select-bucket"))
        .send()
        .await
        .unwrap();

    // Upload JSON data
    let json_data = r#"{"name":"Alice","age":30}
{"name":"Bob","age":25}
{"name":"Charlie","age":35}"#;

    server
        .client
        .put(server.url("/select-bucket/users.json"))
        .header("Content-Type", "application/json")
        .body(json_data)
        .send()
        .await
        .unwrap();

    // Execute S3 Select with WHERE filter
    let select_request = serde_json::json!({
        "Expression": "SELECT * FROM s3object WHERE age > 28",
        "ExpressionType": "SQL",
        "InputSerialization": {
            "JSON": { "Type": "LINES" }
        },
        "OutputSerialization": {
            "JSON": { "RecordDelimiter": "\n" }
        }
    });

    let resp = server
        .client
        .post(server.url("/select-bucket/users.json?select"))
        .json(&select_request)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let result = resp.text().await.unwrap();

    // Should contain Alice (30) and Charlie (35), but not Bob (25)
    assert!(result.contains("Alice"), "Should contain Alice");
    assert!(result.contains("Charlie"), "Should contain Charlie");
    assert!(
        !result.contains("Bob"),
        "Should NOT contain Bob (age <= 28)"
    );
}

#[cfg(feature = "s3-select")]
#[tokio::test]
async fn test_s3_select_csv() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/csv-bucket"))
        .send()
        .await
        .unwrap();

    // Upload CSV data
    let csv_data = "name,age,city\nAlice,30,NYC\nBob,25,LA\nCharlie,35,Chicago";

    server
        .client
        .put(server.url("/csv-bucket/users.csv"))
        .header("Content-Type", "text/csv")
        .body(csv_data)
        .send()
        .await
        .unwrap();

    // Execute S3 Select with projection
    let select_request = serde_json::json!({
        "Expression": "SELECT name, city FROM s3object WHERE age > 26",
        "ExpressionType": "SQL",
        "InputSerialization": {
            "CSV": {
                "FileHeaderInfo": "USE",
                "FieldDelimiter": ",",
                "RecordDelimiter": "\n"
            }
        },
        "OutputSerialization": {
            "JSON": { "RecordDelimiter": "\n" }
        }
    });

    let resp = server
        .client
        .post(server.url("/csv-bucket/users.csv?select"))
        .json(&select_request)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let result = resp.text().await.unwrap();

    // Should contain Alice and Charlie
    assert!(result.contains("Alice"), "Should contain Alice");
    assert!(result.contains("Charlie"), "Should contain Charlie");
    // Bob should be filtered out (age 25 <= 26)
    assert!(!result.contains("Bob"), "Should NOT contain Bob");
}

#[cfg(feature = "s3-select")]
#[tokio::test]
async fn test_s3_select_limit() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/limit-bucket"))
        .send()
        .await
        .unwrap();

    // Upload JSON data with many records
    let json_data = (1..=10)
        .map(|i| format!(r#"{{"id":{},"value":"item{}"}}"#, i, i))
        .collect::<Vec<_>>()
        .join("\n");

    server
        .client
        .put(server.url("/limit-bucket/items.json"))
        .header("Content-Type", "application/json")
        .body(json_data)
        .send()
        .await
        .unwrap();

    // Execute S3 Select with LIMIT
    let select_request = serde_json::json!({
        "Expression": "SELECT * FROM s3object LIMIT 3",
        "ExpressionType": "SQL",
        "InputSerialization": {
            "JSON": { "Type": "LINES" }
        },
        "OutputSerialization": {
            "JSON": { "RecordDelimiter": "\n" }
        }
    });

    let resp = server
        .client
        .post(server.url("/limit-bucket/items.json?select"))
        .json(&select_request)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let result = resp.text().await.unwrap();

    // Count the number of JSON objects (lines with "id")
    let count = result
        .lines()
        .filter(|line| line.contains("\"id\""))
        .count();
    assert_eq!(count, 3, "Should return exactly 3 records");
}

// =============================================================================
// Lifecycle Management Tests
// =============================================================================

#[tokio::test]
async fn test_lifecycle_get_no_config() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/lifecycle-bucket"))
        .send()
        .await
        .unwrap();

    // Get lifecycle (should return 404 when no config exists)
    let resp = server
        .client
        .get(server.url("/lifecycle-bucket?lifecycle"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_lifecycle_put_and_get() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/lifecycle-test"))
        .send()
        .await
        .unwrap();

    // Put lifecycle configuration
    let lifecycle_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration>
    <Rule>
        <ID>ExpireLogs</ID>
        <Status>Enabled</Status>
        <Filter>
            <Prefix>logs/</Prefix>
        </Filter>
        <Expiration>
            <Days>30</Days>
        </Expiration>
    </Rule>
    <Rule>
        <ID>ArchiveData</ID>
        <Status>Enabled</Status>
        <Filter>
            <Prefix>data/</Prefix>
        </Filter>
        <Transition>
            <Days>90</Days>
            <StorageClass>GLACIER</StorageClass>
        </Transition>
    </Rule>
</LifecycleConfiguration>"#;

    let resp = server
        .client
        .put(server.url("/lifecycle-test?lifecycle"))
        .header("Content-Type", "application/xml")
        .body(lifecycle_xml)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Get lifecycle configuration
    let resp = server
        .client
        .get(server.url("/lifecycle-test?lifecycle"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    // Verify the response contains our rules
    assert!(
        body.contains("<LifecycleConfiguration>"),
        "Should have LifecycleConfiguration"
    );
    assert!(
        body.contains("ExpireLogs"),
        "Should contain ExpireLogs rule"
    );
    assert!(
        body.contains("ArchiveData"),
        "Should contain ArchiveData rule"
    );
    assert!(body.contains("logs/"), "Should contain logs/ prefix");
    assert!(body.contains("data/"), "Should contain data/ prefix");
    assert!(
        body.contains("<Days>30</Days>"),
        "Should contain 30 days expiration"
    );
    assert!(
        body.contains("GLACIER"),
        "Should contain GLACIER storage class"
    );
}

#[tokio::test]
async fn test_lifecycle_delete() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/delete-lifecycle"))
        .send()
        .await
        .unwrap();

    // Put lifecycle configuration
    let lifecycle_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration>
    <Rule>
        <ID>TestRule</ID>
        <Status>Enabled</Status>
        <Expiration>
            <Days>7</Days>
        </Expiration>
    </Rule>
</LifecycleConfiguration>"#;

    server
        .client
        .put(server.url("/delete-lifecycle?lifecycle"))
        .header("Content-Type", "application/xml")
        .body(lifecycle_xml)
        .send()
        .await
        .unwrap();

    // Verify it was set
    let resp = server
        .client
        .get(server.url("/delete-lifecycle?lifecycle"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Delete lifecycle configuration
    let resp = server
        .client
        .delete(server.url("/delete-lifecycle?lifecycle"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);

    // Verify it was deleted (should return 404)
    let resp = server
        .client
        .get(server.url("/delete-lifecycle?lifecycle"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_lifecycle_noncurrent_version_rules() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/version-lifecycle"))
        .send()
        .await
        .unwrap();

    // Put lifecycle with noncurrent version rules
    let lifecycle_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration>
    <Rule>
        <ID>CleanOldVersions</ID>
        <Status>Enabled</Status>
        <NoncurrentVersionExpiration>
            <NoncurrentDays>30</NoncurrentDays>
            <NewerNoncurrentVersions>3</NewerNoncurrentVersions>
        </NoncurrentVersionExpiration>
        <NoncurrentVersionTransition>
            <NoncurrentDays>7</NoncurrentDays>
            <StorageClass>STANDARD_IA</StorageClass>
        </NoncurrentVersionTransition>
    </Rule>
</LifecycleConfiguration>"#;

    let resp = server
        .client
        .put(server.url("/version-lifecycle?lifecycle"))
        .header("Content-Type", "application/xml")
        .body(lifecycle_xml)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Get and verify
    let resp = server
        .client
        .get(server.url("/version-lifecycle?lifecycle"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(
        body.contains("CleanOldVersions"),
        "Should contain CleanOldVersions rule"
    );
    assert!(
        body.contains("NoncurrentVersionExpiration"),
        "Should have NoncurrentVersionExpiration"
    );
    assert!(
        body.contains("NoncurrentVersionTransition"),
        "Should have NoncurrentVersionTransition"
    );
    assert!(
        body.contains("<NoncurrentDays>30</NoncurrentDays>"),
        "Should have 30 noncurrent days for expiration"
    );
    assert!(
        body.contains("<NewerNoncurrentVersions>3</NewerNoncurrentVersions>"),
        "Should keep 3 newer versions"
    );
}

// =============================================================================
// Notification Configuration Tests
// =============================================================================

#[tokio::test]
async fn test_notification_get_empty() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/notif-bucket"))
        .send()
        .await
        .unwrap();

    // Get notification (should return empty config, not 404)
    let resp = server
        .client
        .get(server.url("/notif-bucket?notification"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("<NotificationConfiguration>"),
        "Should have NotificationConfiguration element"
    );
}

#[tokio::test]
async fn test_notification_put_and_get() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/notif-test"))
        .send()
        .await
        .unwrap();

    // Put notification configuration with HPC-Channels
    let notification_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <HpcChannelConfiguration>
        <Id>ml-events</Id>
        <ChannelId>hpc.storage.events</ChannelId>
        <Event>s3:ObjectCreated:*</Event>
        <Event>s3:ObjectRemoved:*</Event>
        <Filter>
            <S3Key>
                <FilterRule>
                    <Name>prefix</Name>
                    <Value>checkpoints/</Value>
                </FilterRule>
            </S3Key>
        </Filter>
    </HpcChannelConfiguration>
</NotificationConfiguration>"#;

    let resp = server
        .client
        .put(server.url("/notif-test?notification"))
        .header("Content-Type", "application/xml")
        .body(notification_xml)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Get notification configuration
    let resp = server
        .client
        .get(server.url("/notif-test?notification"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(
        body.contains("ml-events"),
        "Should contain configuration ID"
    );
    assert!(
        body.contains("hpc.storage.events"),
        "Should contain HPC channel ID"
    );
    assert!(
        body.contains("s3:ObjectCreated:*"),
        "Should contain ObjectCreated event"
    );
    assert!(
        body.contains("checkpoints/"),
        "Should contain prefix filter"
    );
}

#[tokio::test]
async fn test_notification_with_topic() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/topic-notif"))
        .send()
        .await
        .unwrap();

    // Put notification configuration with SNS topic
    let notification_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <TopicConfiguration>
        <Id>image-uploads</Id>
        <Topic>arn:aws:sns:us-east-1:123456789012:image-notifications</Topic>
        <Event>s3:ObjectCreated:Put</Event>
        <Filter>
            <S3Key>
                <FilterRule>
                    <Name>suffix</Name>
                    <Value>.jpg</Value>
                </FilterRule>
            </S3Key>
        </Filter>
    </TopicConfiguration>
</NotificationConfiguration>"#;

    let resp = server
        .client
        .put(server.url("/topic-notif?notification"))
        .header("Content-Type", "application/xml")
        .body(notification_xml)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Get and verify
    let resp = server
        .client
        .get(server.url("/topic-notif?notification"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();

    assert!(
        body.contains("TopicConfiguration"),
        "Should have TopicConfiguration"
    );
    assert!(
        body.contains("image-uploads"),
        "Should contain configuration ID"
    );
    assert!(body.contains("arn:aws:sns"), "Should contain SNS topic ARN");
}

#[tokio::test]
async fn test_notification_delete() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/delete-notif"))
        .send()
        .await
        .unwrap();

    // Put notification configuration
    let notification_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration>
    <HpcChannelConfiguration>
        <Id>test</Id>
        <ChannelId>hpc.test</ChannelId>
        <Event>s3:ObjectCreated:*</Event>
    </HpcChannelConfiguration>
</NotificationConfiguration>"#;

    server
        .client
        .put(server.url("/delete-notif?notification"))
        .header("Content-Type", "application/xml")
        .body(notification_xml)
        .send()
        .await
        .unwrap();

    // Verify it was set
    let resp = server
        .client
        .get(server.url("/delete-notif?notification"))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("hpc.test"),
        "Should have the notification config"
    );

    // Delete notification configuration
    let resp = server
        .client
        .delete(server.url("/delete-notif?notification"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);

    // Verify it was deleted (should return empty config)
    let resp = server
        .client
        .get(server.url("/delete-notif?notification"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("hpc.test"),
        "Should not have the notification config anymore"
    );
}

// =============================================================================
// LazyGet Tests (Phase 2: Parcode Integration)
// =============================================================================

#[tokio::test]
async fn test_lazy_get_basic() {
    let server = TestServer::new().await;

    // Create bucket and object
    server
        .client
        .put(server.url("/lazy-test"))
        .send()
        .await
        .unwrap();

    let content = b"test object data for lazy get";
    server
        .client
        .put(server.url("/lazy-test/checkpoint.bin"))
        .body(content.to_vec())
        .send()
        .await
        .unwrap();

    // Request specific fields (note: with LocalBackend, get_fields returns empty FieldData)
    let resp = server
        .client
        .post(server.url("/api/v1/lazy/lazy-test/checkpoint.bin"))
        .json(&serde_json::json!({
            "fields": ["epoch", "step", "optimizer_state"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify response structure
    assert!(body.get("requested").is_some());
    assert!(body.get("returned").is_some());
    assert!(body.get("bytes_avoided").is_some());
    assert!(body.get("object_size").is_some());

    // Check that object_size matches the content size
    assert_eq!(body["object_size"], content.len() as u64);
    assert_eq!(body["requested"], 3); // We requested 3 fields
}

#[tokio::test]
async fn test_lazy_get_nonexistent_object() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/lazy-error"))
        .send()
        .await
        .unwrap();

    // Try to lazy get from nonexistent object
    let resp = server
        .client
        .post(server.url("/api/v1/lazy/lazy-error/nonexistent.bin"))
        .json(&serde_json::json!({
            "fields": ["field1"]
        }))
        .send()
        .await
        .unwrap();

    // Should return 404
    assert_eq!(resp.status(), 404);
}

// =============================================================================
// CollectiveRead Tests (Phase 2: RMPI Integration)
// =============================================================================

#[tokio::test]
async fn test_collective_read_basic() {
    let server = TestServer::new().await;

    // Create bucket and multiple objects
    server
        .client
        .put(server.url("/collective-test"))
        .send()
        .await
        .unwrap();

    for i in 0..4 {
        let content = format!("shard data {}", i);
        server
            .client
            .put(server.url(&format!("/collective-test/shard_{}.pt", i)))
            .body(content)
            .send()
            .await
            .unwrap();
    }

    // Collective read across 2 ranks
    let resp = server
        .client
        .post(server.url("/api/v1/collective/read"))
        .json(&serde_json::json!({
            "keys": [
                {"bucket": "collective-test", "key": "shard_0.pt"},
                {"bucket": "collective-test", "key": "shard_1.pt"},
                {"bucket": "collective-test", "key": "shard_2.pt"},
                {"bucket": "collective-test", "key": "shard_3.pt"}
            ],
            "rank_count": 2
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify response structure
    assert_eq!(body["object_count"], 4);
    assert!(body["total_bytes"].as_u64().unwrap() > 0);

    // Should have results for each rank
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);

    // Each rank should have 2 objects (round-robin distribution)
    assert_eq!(results[0]["objects"].as_array().unwrap().len(), 2);
    assert_eq!(results[1]["objects"].as_array().unwrap().len(), 2);

    // Check rank IDs
    assert_eq!(results[0]["rank"], 0);
    assert_eq!(results[1]["rank"], 1);
}

#[tokio::test]
async fn test_collective_read_single_rank() {
    let server = TestServer::new().await;

    // Create bucket and objects
    server
        .client
        .put(server.url("/single-rank"))
        .send()
        .await
        .unwrap();

    for i in 0..3 {
        let content = format!("object {}", i);
        server
            .client
            .put(server.url(&format!("/single-rank/obj_{}.bin", i)))
            .body(content)
            .send()
            .await
            .unwrap();
    }

    // Read with single rank (all objects go to rank 0)
    let resp = server
        .client
        .post(server.url("/api/v1/collective/read"))
        .json(&serde_json::json!({
            "keys": [
                {"bucket": "single-rank", "key": "obj_0.bin"},
                {"bucket": "single-rank", "key": "obj_1.bin"},
                {"bucket": "single-rank", "key": "obj_2.bin"}
            ],
            "rank_count": 1
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // All objects should be on rank 0
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["objects"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_collective_read_zero_ranks_error() {
    let server = TestServer::new().await;

    // Create bucket
    server
        .client
        .put(server.url("/zero-ranks"))
        .send()
        .await
        .unwrap();

    // Try with zero ranks
    let resp = server
        .client
        .post(server.url("/api/v1/collective/read"))
        .json(&serde_json::json!({
            "keys": [
                {"bucket": "zero-ranks", "key": "obj.bin"}
            ],
            "rank_count": 0
        }))
        .send()
        .await
        .unwrap();

    // Should return 400 Bad Request
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_collective_read_empty_keys() {
    let server = TestServer::new().await;

    // Collective read with empty keys
    let resp = server
        .client
        .post(server.url("/api/v1/collective/read"))
        .json(&serde_json::json!({
            "keys": [],
            "rank_count": 4
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["object_count"], 0);
    assert_eq!(body["total_bytes"], 0);
}

// =============================================================================
// GPU Operations Tests (Phase 2)
// =============================================================================

#[tokio::test]
async fn test_gpu_hash() {
    let server = TestServer::new().await;

    // Create bucket and object
    server
        .client
        .put(server.url("/gpu-hash-test"))
        .send()
        .await
        .unwrap();

    let content = b"test data for GPU hashing";
    server
        .client
        .put(server.url("/gpu-hash-test/data.bin"))
        .body(content.to_vec())
        .send()
        .await
        .unwrap();

    // Request GPU hash
    let resp = server
        .client
        .post(server.url("/api/v1/gpu/hash"))
        .json(&serde_json::json!({
            "bucket": "gpu-hash-test",
            "key": "data.bin",
            "algorithm": "blake3"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify response structure
    assert!(body.get("hash").is_some());
    assert!(body.get("time_ms").is_some());
    assert!(body.get("throughput_gbps").is_some());
    assert!(body.get("gpu_used").is_some());
    assert_eq!(body["object_size"], content.len() as u64);

    // Verify hash is correct (BLAKE3 produces 64 hex chars)
    let hash = body["hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
}

#[tokio::test]
async fn test_gpu_capabilities() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/api/v1/gpu/capabilities"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Should have available field
    assert!(body.get("available").is_some());
    // GPU might not be available in test environment, but field should exist
    assert!(body["available"].is_boolean());
}

#[tokio::test]
async fn test_gpu_stats() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/api/v1/gpu/stats"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify response structure
    assert!(body.get("gpu_enabled").is_some());
    assert!(body.get("gpu_available").is_some());
    assert!(body.get("gpu_threshold_bytes").is_some());
    assert!(body.get("supported_ops").is_some());

    // Check supported operations
    let ops = body["supported_ops"].as_array().unwrap();
    assert!(ops.iter().any(|o| o == "blake3"));
    assert!(ops.iter().any(|o| o == "chacha20-poly1305"));
}

// =============================================================================
// ZK Proof Operations Tests (Phase 2)
// =============================================================================

#[tokio::test]
async fn test_zk_prove() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .post(server.url("/api/v1/zk/prove"))
        .json(&serde_json::json!({
            "proof_type": "simulated",
            "public_inputs": ["deadbeef"],
            "witness": ["cafebabe"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify response structure
    assert!(body.get("proof").is_some());
    assert!(body.get("proof_type").is_some());
    assert!(body.get("proof_size").is_some());
    assert!(body.get("time_ms").is_some());
    assert!(body.get("gpu_used").is_some());

    // Check proof type
    assert_eq!(body["proof_type"], "simulated");
    // Simulated proofs are 256 bytes = 512 hex chars
    assert_eq!(body["proof_size"], 256);
}

#[tokio::test]
async fn test_zk_verify() {
    let server = TestServer::new().await;

    // First generate a proof
    let prove_resp = server
        .client
        .post(server.url("/api/v1/zk/prove"))
        .json(&serde_json::json!({
            "proof_type": "simulated",
            "public_inputs": ["deadbeef"],
            "witness": ["cafebabe"]
        }))
        .send()
        .await
        .unwrap();

    let prove_body: serde_json::Value = prove_resp.json().await.unwrap();
    let proof = prove_body["proof"].as_str().unwrap();

    // Now verify it
    let resp = server
        .client
        .post(server.url("/api/v1/zk/verify"))
        .json(&serde_json::json!({
            "proof": proof,
            "proof_type": "simulated",
            "public_inputs": ["deadbeef"]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Should be valid
    assert!(body.get("valid").is_some());
    assert!(body.get("time_ms").is_some());
    assert!(body.get("verification_cost").is_some());
}

#[tokio::test]
async fn test_zk_verified_read() {
    let server = TestServer::new().await;

    // Create bucket and object
    server
        .client
        .put(server.url("/zk-verify-test"))
        .send()
        .await
        .unwrap();

    let content = b"data with merkle proof";
    server
        .client
        .put(server.url("/zk-verify-test/verified.bin"))
        .body(content.to_vec())
        .send()
        .await
        .unwrap();

    // Request verified read
    let resp = server
        .client
        .post(server.url("/api/v1/zk/verified-read"))
        .json(&serde_json::json!({
            "bucket": "zk-verify-test",
            "key": "verified.bin"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify response structure
    assert!(body.get("data").is_some());
    assert!(body.get("size").is_some());
    assert!(body.get("content_hash").is_some());
    assert!(body.get("merkle_root").is_some());
    assert!(body.get("merkle_path").is_some());
    assert!(body.get("verified").is_some());

    // Should be verified
    assert_eq!(body["verified"], true);
    assert_eq!(body["size"], content.len() as u64);
}

#[tokio::test]
async fn test_zk_proof_types() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/api/v1/zk/proof-types"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify response structure
    assert!(body.get("supported").is_some());

    let supported = body["supported"].as_array().unwrap();
    assert!(!supported.is_empty());

    // Check for expected proof types
    let names: Vec<&str> = supported
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();

    assert!(names.contains(&"groth16"));
    assert!(names.contains(&"plonk"));
    assert!(names.contains(&"stark"));
}

#[tokio::test]
async fn test_zk_stats() {
    let server = TestServer::new().await;

    let resp = server
        .client
        .get(server.url("/api/v1/zk/stats"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify response structure
    assert!(body.get("zk_enabled").is_some());
    assert!(body.get("supported_types").is_some());
    assert!(body.get("gpu_proving_available").is_some());

    // Check supported types
    let types = body["supported_types"].as_array().unwrap();
    assert!(types.iter().any(|t| t == "groth16"));
    assert!(types.iter().any(|t| t == "plonk"));
    assert!(types.iter().any(|t| t == "stark"));
}
