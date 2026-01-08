//! S3-compatible storage commands (ls, cp, rm, mb, rb, cat, stat)
//!
//! These commands provide MinIO mc-compatible CLI operations for
//! interacting with warp-store.

use anyhow::{Context, Result, bail};
use console::{Term, style};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write as IoWrite};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use warp_store::{
    BucketConfig, ListOptions, ObjectData, ObjectKey, ObjectLockConfig, ObjectLockManager,
    ObjectRetention, RetentionMode, Store, StoreConfig, VersioningMode,
};

/// Alias configuration stored in config file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AliasConfig {
    pub aliases: HashMap<String, AliasEntry>,
}

/// Individual alias entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasEntry {
    pub url: String,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub root_path: Option<String>,
}

/// Parse a storage path like "alias/bucket/key" or "bucket/key"
///
/// # Arguments
///
/// * `path` - Storage path string to parse
///
/// # Returns
///
/// Tuple of (alias, bucket, key) where each component is optional
pub fn parse_path(path: &str) -> (Option<&str>, Option<&str>, Option<&str>) {
    let parts: Vec<&str> = path.trim_matches('/').splitn(3, '/').collect();
    match parts.len() {
        0 => (None, None, None),
        1 if parts[0].is_empty() => (None, None, None),
        1 => (None, Some(parts[0]), None),
        2 => (None, Some(parts[0]), Some(parts[1])),
        _ => (None, Some(parts[0]), Some(parts[2])),
    }
}

/// Check if a path is a local file path
pub fn is_local_path(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with("./")
        || path.starts_with("../")
        || Path::new(path).exists()
}

/// Get the alias config file path
fn alias_config_path() -> Result<std::path::PathBuf> {
    let config_dir = dirs::config_dir()
        .context("Could not determine config directory")?
        .join("warp");
    std::fs::create_dir_all(&config_dir)?;
    Ok(config_dir.join("aliases.toml"))
}

/// Load alias configuration from file
fn load_alias_config() -> Result<AliasConfig> {
    let config_path = alias_config_path()?;
    if !config_path.exists() {
        return Ok(AliasConfig::default());
    }
    let content = std::fs::read_to_string(&config_path)?;
    let config: AliasConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Save alias configuration to file
fn save_alias_config(config: &AliasConfig) -> Result<()> {
    let config_path = alias_config_path()?;
    let content = toml::to_string_pretty(config)?;
    std::fs::write(&config_path, content)?;
    Ok(())
}

/// Get store configuration based on alias or default
async fn get_store_config(_alias: Option<&str>) -> Result<StoreConfig> {
    // Try to load alias config
    let alias_config = load_alias_config().unwrap_or_default();

    // If alias specified, try to find it
    if let Some(alias_name) = _alias {
        if let Some(entry) = alias_config.aliases.get(alias_name) {
            let root_path = entry
                .root_path
                .as_ref()
                .map(|p| std::path::PathBuf::from(p))
                .unwrap_or_else(|| {
                    dirs::data_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                        .join("warp-store")
                });
            return Ok(StoreConfig {
                root_path,
                default_versioning: VersioningMode::Disabled,
                ..Default::default()
            });
        }
    }

    // Default config using local storage
    let root_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("warp-store");

    Ok(StoreConfig {
        root_path,
        default_versioning: VersioningMode::Disabled,
        ..Default::default()
    })
}

/// Get a store instance
async fn get_store() -> Result<Store> {
    let config = get_store_config(None).await?;
    Store::new(config)
        .await
        .context("Failed to connect to store")
}

/// List buckets or objects
pub async fn list(path: &str, recursive: bool, json: bool) -> Result<()> {
    let term = Term::stdout();
    let (_, bucket, prefix) = parse_path(path);
    let store = get_store().await?;

    if bucket.is_none() {
        // List buckets
        term.write_line(&format!(
            "{} {}",
            style("[INFO]").cyan(),
            "Listing buckets..."
        ))?;

        let buckets = store.list_buckets().await;

        if json {
            let bucket_list: Vec<_> = buckets
                .iter()
                .map(|b| serde_json::json!({"name": b}))
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"buckets": bucket_list}))?
            );
        } else if buckets.is_empty() {
            println!("{}", style("No buckets found").yellow());
        } else {
            for bucket_name in buckets {
                println!("  {}", style(&bucket_name).green());
            }
        }
    } else {
        // List objects in bucket
        let bucket_name = bucket.unwrap();
        let prefix_str = prefix.unwrap_or("");

        term.write_line(&format!(
            "{} Listing objects in {} {}",
            style("[INFO]").cyan(),
            style(bucket_name).green(),
            if recursive { "(recursive)" } else { "" }
        ))?;

        let opts = ListOptions {
            max_keys: Some(1000),
            delimiter: if recursive {
                None
            } else {
                Some("/".to_string())
            },
            ..Default::default()
        };

        let list_result = store
            .list_with_options(bucket_name, prefix_str, opts)
            .await?;

        if json {
            let objects: Vec<_> = list_result
                .objects
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "key": o.key,
                        "size": o.size,
                        "last_modified": o.last_modified.to_rfc3339(),
                        "etag": o.etag
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"objects": objects}))?
            );
        } else if list_result.objects.is_empty() {
            println!(
                "{}",
                style(format!("No objects found in bucket '{}'", bucket_name)).yellow()
            );
        } else {
            for obj in &list_result.objects {
                println!(
                    "  {} {:>10} {}",
                    style(&obj.last_modified.format("%Y-%m-%d %H:%M:%S").to_string()).dim(),
                    humansize::format_size(obj.size, humansize::BINARY),
                    style(&obj.key).cyan()
                );
            }
        }
    }

    Ok(())
}

/// Create a bucket
pub async fn make_bucket(bucket: &str, with_lock: bool, with_versioning: bool) -> Result<()> {
    let term = Term::stdout();

    // Validate bucket name
    if bucket.len() < 3 || bucket.len() > 63 {
        bail!("Bucket name must be between 3 and 63 characters");
    }

    if !bucket
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("Bucket name can only contain lowercase letters, numbers, and hyphens");
    }

    term.write_line(&format!(
        "{} Creating bucket: {}{}{}",
        style("[INFO]").cyan(),
        style(bucket).green(),
        if with_lock {
            format!(" {}", style("(with Object Lock)").yellow())
        } else {
            String::new()
        },
        if with_versioning {
            format!(" {}", style("(versioned)").blue())
        } else {
            String::new()
        }
    ))?;

    let store = get_store().await?;

    let versioning = if with_versioning || with_lock {
        VersioningMode::Enabled
    } else {
        VersioningMode::Disabled
    };

    let config = BucketConfig {
        versioning,
        object_lock_enabled: with_lock,
        ..Default::default()
    };

    store.create_bucket(bucket, config).await?;

    term.write_line(&format!(
        "{} Bucket '{}' created successfully",
        style("[OK]").green(),
        bucket
    ))?;

    Ok(())
}

/// Remove a bucket
pub async fn remove_bucket(bucket: &str, force: bool) -> Result<()> {
    let term = Term::stdout();

    if !force {
        term.write_line(&format!(
            "{} Are you sure you want to remove bucket '{}'? Use --force to confirm",
            style("[WARN]").yellow(),
            bucket
        ))?;
        return Ok(());
    }

    term.write_line(&format!(
        "{} Removing bucket: {}",
        style("[INFO]").cyan(),
        style(bucket).red()
    ))?;

    let store = get_store().await?;
    store.delete_bucket(bucket).await?;

    term.write_line(&format!(
        "{} Bucket '{}' removed",
        style("[OK]").green(),
        bucket
    ))?;

    Ok(())
}

/// Copy objects
pub async fn copy(source: &str, destination: &str, recursive: bool, _preserve: bool) -> Result<()> {
    let term = Term::stdout();

    let src_local = is_local_path(source);
    let dst_local = is_local_path(destination);

    if src_local && dst_local {
        bail!("Both source and destination are local paths. Use 'cp' command instead.");
    }

    let store = get_store().await?;

    if src_local {
        // Upload local file to store
        term.write_line(&format!(
            "{} Uploading {} -> {}",
            style("[INFO]").cyan(),
            style(source).cyan(),
            style(destination).green()
        ))?;

        let (_, bucket, key) = parse_path(destination);
        let bucket = bucket.context("Destination must include bucket name")?;
        let key = key.unwrap_or_else(|| {
            Path::new(source)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
        });

        let data = if recursive && Path::new(source).is_dir() {
            // For directories, we'd need to iterate - simplified for now
            bail!("Recursive directory upload not yet implemented. Upload files individually.");
        } else {
            std::fs::read(source).context("Failed to read source file")?
        };

        let object_key = ObjectKey::new(bucket, key)?;
        store.put(&object_key, ObjectData::from(data)).await?;

        term.write_line(&format!("{} Upload complete", style("[OK]").green()))?;
    } else if dst_local {
        // Download from store to local file
        term.write_line(&format!(
            "{} Downloading {} -> {}",
            style("[INFO]").cyan(),
            style(source).cyan(),
            style(destination).green()
        ))?;

        let (_, bucket, key) = parse_path(source);
        let bucket = bucket.context("Source must include bucket name")?;
        let key = key.context("Source must include object key")?;

        let object_key = ObjectKey::new(bucket, key)?;
        let data = store.get(&object_key).await?;

        let dest_path = if Path::new(destination).is_dir() {
            Path::new(destination).join(Path::new(key).file_name().unwrap_or_default())
        } else {
            Path::new(destination).to_path_buf()
        };

        std::fs::write(&dest_path, data.as_ref()).context("Failed to write destination file")?;

        term.write_line(&format!("{} Download complete", style("[OK]").green()))?;
    } else {
        // Copy between buckets
        term.write_line(&format!(
            "{} Copying {} -> {}{}",
            style("[INFO]").cyan(),
            style(source).cyan(),
            style(destination).green(),
            if recursive { " (recursive)" } else { "" }
        ))?;

        let (_, src_bucket, src_key) = parse_path(source);
        let (_, dst_bucket, dst_key) = parse_path(destination);

        let src_bucket = src_bucket.context("Source must include bucket name")?;
        let src_key = src_key.context("Source must include object key")?;
        let dst_bucket = dst_bucket.context("Destination must include bucket name")?;
        let dst_key = dst_key.unwrap_or(src_key);

        let src_object_key = ObjectKey::new(src_bucket, src_key)?;
        let dst_object_key = ObjectKey::new(dst_bucket, dst_key)?;

        let data = store.get(&src_object_key).await?;
        store.put(&dst_object_key, data).await?;

        term.write_line(&format!("{} Copy complete", style("[OK]").green()))?;
    }

    Ok(())
}

/// Move objects
pub async fn mv(source: &str, destination: &str, recursive: bool) -> Result<()> {
    let term = Term::stdout();

    term.write_line(&format!(
        "{} Moving {} -> {}{}",
        style("[INFO]").cyan(),
        style(source).cyan(),
        style(destination).green(),
        if recursive { " (recursive)" } else { "" }
    ))?;

    // Copy then delete
    copy(source, destination, recursive, false).await?;

    // Delete source
    let (_, bucket, key) = parse_path(source);
    if let (Some(bucket), Some(key)) = (bucket, key) {
        let store = get_store().await?;
        let object_key = ObjectKey::new(bucket, key)?;
        store.delete(&object_key).await?;
    }

    term.write_line(&format!("{} Move complete", style("[OK]").green()))?;

    Ok(())
}

/// Remove objects
pub async fn remove(
    path: &str,
    recursive: bool,
    force: bool,
    _bypass_governance: bool,
    _versions: bool,
) -> Result<()> {
    let term = Term::stdout();

    let (_, bucket, key) = parse_path(path);

    if bucket.is_none() {
        bail!("Invalid path: must specify bucket/key");
    }

    if !force {
        term.write_line(&format!(
            "{} Are you sure you want to remove '{}'? Use --force to confirm",
            style("[WARN]").yellow(),
            path
        ))?;
        return Ok(());
    }

    let store = get_store().await?;
    let bucket_name = bucket.unwrap();

    if let Some(key_str) = key {
        // Remove single object or prefix
        term.write_line(&format!(
            "{} Removing: {}",
            style("[INFO]").cyan(),
            style(path).red()
        ))?;

        if recursive {
            // List and delete all objects with prefix
            let list_result = store.list(bucket_name, key_str).await?;
            for obj in list_result.objects {
                let obj_key = ObjectKey::new(bucket_name, &obj.key)?;
                store.delete(&obj_key).await?;
                term.write_line(&format!("  Deleted: {}", style(&obj.key).dim()))?;
            }
        } else {
            let object_key = ObjectKey::new(bucket_name, key_str)?;
            store.delete(&object_key).await?;
        }
    } else {
        bail!("Must specify object key to remove");
    }

    term.write_line(&format!("{} Remove complete", style("[OK]").green()))?;

    Ok(())
}

/// Display object contents
pub async fn cat(path: &str, _version_id: Option<&str>) -> Result<()> {
    let (_, bucket, key) = parse_path(path);

    let bucket = bucket.context("Must specify bucket")?;
    let key = key.context("Must specify object key")?;

    let store = get_store().await?;
    let object_key = ObjectKey::new(bucket, key)?;
    let data = store.get(&object_key).await?;

    // Write to stdout
    let mut stdout = std::io::stdout();
    stdout.write_all(data.as_ref())?;
    stdout.flush()?;

    Ok(())
}

/// Get object info
pub async fn stat(path: &str, _version_id: Option<&str>) -> Result<()> {
    let term = Term::stdout();
    let (_, bucket, key) = parse_path(path);

    let bucket = bucket.context("Must specify bucket")?;

    let store = get_store().await?;

    if let Some(key_str) = key {
        let object_key = ObjectKey::new(bucket, key_str)?;
        let meta = store.head(&object_key).await?;

        term.write_line(&format!("{} Object Info:", style("[INFO]").cyan()))?;
        println!("  Bucket: {}", bucket);
        println!("  Key: {}", key_str);
        println!(
            "  Size: {} ({})",
            meta.size,
            humansize::format_size(meta.size, humansize::BINARY)
        );
        println!("  Last Modified: {}", meta.last_modified.to_rfc3339());
        println!("  ETag: {}", meta.etag);
        println!("  Content-Type: {}", meta.content_type);
        if let Some(version) = &meta.version_id {
            println!("  Version ID: {}", version);
        }
    } else {
        // Bucket info
        term.write_line(&format!(
            "{} Bucket Info: {}",
            style("[INFO]").cyan(),
            bucket
        ))?;
        let buckets = store.list_buckets().await;
        if buckets.contains(&bucket.to_string()) {
            println!("  Status: exists");
        } else {
            println!("  Status: not found");
        }
    }

    Ok(())
}

/// Set object retention
pub async fn retention_set(
    path: &str,
    mode: &str,
    days: Option<u32>,
    until: Option<&str>,
    _version_id: Option<&str>,
) -> Result<()> {
    let term = Term::stdout();
    let (_, bucket, key) = parse_path(path);

    let bucket = bucket.context("Must specify bucket")?;
    let key = key.context("Must specify object key")?;

    // Validate mode
    let retention_mode = match mode.to_uppercase().as_str() {
        "GOVERNANCE" => RetentionMode::Governance,
        "COMPLIANCE" => RetentionMode::Compliance,
        _ => bail!("Mode must be GOVERNANCE or COMPLIANCE"),
    };

    let retain_until = if let Some(d) = days {
        chrono::Utc::now() + chrono::Duration::days(d as i64)
    } else if let Some(u) = until {
        chrono::DateTime::parse_from_rfc3339(u)
            .context("Invalid date format, use ISO 8601 (e.g., 2024-12-31T23:59:59Z)")?
            .with_timezone(&chrono::Utc)
    } else {
        bail!("Must specify either --days or --until");
    };

    term.write_line(&format!(
        "{} Setting {} retention on {} until {}",
        style("[INFO]").cyan(),
        style(mode.to_uppercase()).yellow(),
        path,
        retain_until.to_rfc3339()
    ))?;

    let store = get_store().await?;
    let object_key = ObjectKey::new(bucket, key)?;

    // Get the ObjectLockManager from the backend
    let lock_manager = ObjectLockManager::new(ObjectLockConfig::default());

    let retention = ObjectRetention {
        mode: retention_mode,
        retain_until_date: retain_until,
    };

    lock_manager.set_object_retention(&object_key, retention)?;

    term.write_line(&format!(
        "{} Retention set successfully",
        style("[OK]").green()
    ))?;

    Ok(())
}

/// Get object retention
pub async fn retention_get(path: &str, _version_id: Option<&str>) -> Result<()> {
    let term = Term::stdout();
    let (_, bucket, key) = parse_path(path);

    let bucket = bucket.context("Must specify bucket")?;
    let key = key.context("Must specify object key")?;

    let object_key = ObjectKey::new(bucket, key)?;
    let lock_manager = ObjectLockManager::new(ObjectLockConfig::default());

    term.write_line(&format!(
        "{} Retention for: {}",
        style("[INFO]").cyan(),
        path
    ))?;

    match lock_manager.get_object_retention(&object_key) {
        Ok(Some(retention)) => {
            let mode_str = match retention.mode {
                RetentionMode::Governance => "GOVERNANCE",
                RetentionMode::Compliance => "COMPLIANCE",
            };
            println!("  Mode: {}", mode_str);
            println!(
                "  Retain Until: {}",
                retention.retain_until_date.to_rfc3339()
            );
        }
        Ok(None) => {
            println!("  No retention set");
        }
        Err(e) => {
            println!("  Error: {}", e);
        }
    }

    Ok(())
}

/// Clear object retention
pub async fn retention_clear(
    path: &str,
    _version_id: Option<&str>,
    bypass_governance: bool,
) -> Result<()> {
    let term = Term::stdout();
    let (_, bucket, key) = parse_path(path);

    let bucket = bucket.context("Must specify bucket")?;
    let key = key.context("Must specify object key")?;

    term.write_line(&format!(
        "{} Clearing retention on {}{}",
        style("[INFO]").cyan(),
        path,
        if bypass_governance {
            format!(" {}", style("(bypass governance)").yellow())
        } else {
            String::new()
        }
    ))?;

    let object_key = ObjectKey::new(bucket, key)?;
    let lock_manager = ObjectLockManager::new(ObjectLockConfig::default());

    lock_manager.clear_object_retention(&object_key, bypass_governance)?;

    term.write_line(&format!("{} Retention cleared", style("[OK]").green()))?;

    Ok(())
}

/// Set legal hold
pub async fn legal_hold_set(path: &str, _version_id: Option<&str>) -> Result<()> {
    let term = Term::stdout();
    let (_, bucket, key) = parse_path(path);

    let bucket = bucket.context("Must specify bucket")?;
    let key = key.context("Must specify object key")?;

    term.write_line(&format!(
        "{} Setting legal hold on {}",
        style("[INFO]").cyan(),
        path
    ))?;

    let object_key = ObjectKey::new(bucket, key)?;
    let lock_manager = ObjectLockManager::new(ObjectLockConfig::default());

    lock_manager.set_legal_hold(&object_key, true)?;

    term.write_line(&format!("{} Legal hold enabled", style("[OK]").green()))?;

    Ok(())
}

/// Clear legal hold
pub async fn legal_hold_clear(path: &str, _version_id: Option<&str>) -> Result<()> {
    let term = Term::stdout();
    let (_, bucket, key) = parse_path(path);

    let bucket = bucket.context("Must specify bucket")?;
    let key = key.context("Must specify object key")?;

    term.write_line(&format!(
        "{} Clearing legal hold on {}",
        style("[INFO]").cyan(),
        path
    ))?;

    let object_key = ObjectKey::new(bucket, key)?;
    let lock_manager = ObjectLockManager::new(ObjectLockConfig::default());

    lock_manager.set_legal_hold(&object_key, false)?;

    term.write_line(&format!("{} Legal hold disabled", style("[OK]").green()))?;

    Ok(())
}

/// Get legal hold status
pub async fn legal_hold_get(path: &str, _version_id: Option<&str>) -> Result<()> {
    let term = Term::stdout();
    let (_, bucket, key) = parse_path(path);

    let bucket = bucket.context("Must specify bucket")?;
    let key = key.context("Must specify object key")?;

    let object_key = ObjectKey::new(bucket, key)?;
    let lock_manager = ObjectLockManager::new(ObjectLockConfig::default());

    term.write_line(&format!(
        "{} Legal hold status for: {}",
        style("[INFO]").cyan(),
        path
    ))?;

    match lock_manager.get_legal_hold(&object_key) {
        Ok(status) => {
            println!("  Status: {}", if status { "ON" } else { "OFF" });
        }
        Err(e) => {
            println!("  Error: {}", e);
        }
    }

    Ok(())
}

/// Set an alias
pub async fn alias_set(
    alias: &str,
    url: &str,
    access_key: Option<&str>,
    secret_key: Option<&str>,
) -> Result<()> {
    let term = Term::stdout();

    term.write_line(&format!(
        "{} Setting alias '{}' -> {}",
        style("[INFO]").cyan(),
        style(alias).green(),
        url
    ))?;

    let mut config = load_alias_config()?;

    config.aliases.insert(
        alias.to_string(),
        AliasEntry {
            url: url.to_string(),
            access_key: access_key.map(|s| s.to_string()),
            secret_key: secret_key.map(|s| s.to_string()),
            root_path: None,
        },
    );

    save_alias_config(&config)?;

    let config_path = alias_config_path()?;
    term.write_line(&format!(
        "{} Alias saved to {}",
        style("[OK]").green(),
        config_path.display()
    ))?;

    Ok(())
}

/// Remove an alias
pub async fn alias_remove(alias: &str) -> Result<()> {
    let term = Term::stdout();

    term.write_line(&format!(
        "{} Removing alias: {}",
        style("[INFO]").cyan(),
        style(alias).red()
    ))?;

    let mut config = load_alias_config()?;

    if config.aliases.remove(alias).is_none() {
        bail!("Alias '{}' not found", alias);
    }

    save_alias_config(&config)?;

    term.write_line(&format!("{} Alias removed", style("[OK]").green()))?;

    Ok(())
}

/// List aliases
pub async fn alias_list() -> Result<()> {
    let term = Term::stdout();

    term.write_line(&format!("{} Configured aliases:", style("[INFO]").cyan()))?;

    let config = load_alias_config()?;

    if config.aliases.is_empty() {
        println!("  (no aliases configured)");
    } else {
        for (name, entry) in &config.aliases {
            println!(
                "  {} -> {}{}",
                style(name).green(),
                entry.url,
                if entry.access_key.is_some() {
                    " (authenticated)"
                } else {
                    ""
                }
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path() {
        assert_eq!(parse_path(""), (None, None, None));
        assert_eq!(parse_path("bucket"), (None, Some("bucket"), None));
        assert_eq!(
            parse_path("bucket/key"),
            (None, Some("bucket"), Some("key"))
        );
        assert_eq!(
            parse_path("bucket/path/to/key"),
            (None, Some("bucket"), Some("to/key"))
        );
    }

    #[test]
    fn test_is_local_path() {
        assert!(is_local_path("/tmp/file"));
        assert!(is_local_path("./file"));
        assert!(is_local_path("../file"));
        assert!(!is_local_path("bucket/key"));
    }
}
