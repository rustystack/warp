//! Resource constraint tracking for edge devices
//!
//! This module provides constraint tracking for edge resources including:
//! - Battery levels and charging state for mobile devices
//! - Time-based restriction windows (allowed/blocked times)
//! - Daily bandwidth limits and metered connections
//! - Per-edge resource constraint management

use crate::types::EdgeId;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Battery constraints for mobile devices
///
/// Tracks battery level and charging state to prevent draining batteries
/// during storage operations. Upload and download operations have separate
/// minimum battery thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatteryConstraints {
    /// Minimum battery percentage for uploads (default 20)
    pub min_battery_upload: u8,
    /// Minimum battery percentage for downloads (default 15)
    pub min_battery_download: u8,
    /// Current battery level (0-100)
    pub current_level: u8,
    /// Whether device is currently charging
    pub is_charging: bool,
}

impl BatteryConstraints {
    /// Creates new battery constraints with current level and charging state
    #[must_use]
    pub fn new(level: u8, is_charging: bool) -> Self {
        Self {
            min_battery_upload: 20,
            min_battery_download: 15,
            current_level: level.min(100),
            is_charging,
        }
    }

    /// Checks if uploads are allowed based on current battery state
    #[must_use]
    pub const fn can_upload(&self) -> bool {
        self.is_charging || self.current_level >= self.min_battery_upload
    }

    /// Checks if downloads are allowed based on current battery state
    #[must_use]
    pub const fn can_download(&self) -> bool {
        self.is_charging || self.current_level >= self.min_battery_download
    }
}

/// Time window for schedule-based restrictions
///
/// Defines allowed or blocked time windows for edge operations. Multiple
/// time windows can be combined to create complex schedules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Day of week (0=Sunday, 6=Saturday)
    pub day_of_week: u8,
    /// Start hour (0-23)
    pub start_hour: u8,
    /// End hour (0-23)
    pub end_hour: u8,
    /// Whether this is an allowed (true) or blocked (false) window
    pub allow: bool,
}

impl TimeWindow {
    /// Creates a new time window
    #[must_use]
    pub fn new(day: u8, start: u8, end: u8, allow: bool) -> Self {
        Self {
            day_of_week: day.min(6),
            start_hour: start.min(23),
            end_hour: end.min(23),
            allow,
        }
    }

    /// Checks if current time is within this window
    #[must_use]
    pub fn is_active_now(&self) -> bool {
        use chrono::prelude::*;

        let now = Local::now();
        let current_day = now.weekday().num_days_from_sunday() as u8;
        let current_hour = now.hour() as u8;

        if current_day != self.day_of_week {
            return false;
        }

        if self.start_hour <= self.end_hour {
            current_hour >= self.start_hour && current_hour <= self.end_hour
        } else {
            current_hour >= self.start_hour || current_hour <= self.end_hour
        }
    }
}

/// Complete resource constraints for an edge device
///
/// Combines storage limits, bandwidth constraints, battery requirements,
/// and time-based restrictions into a unified constraint model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConstraints {
    /// Maximum storage capacity in bytes
    pub max_storage_bytes: Option<u64>,
    /// Maximum daily bandwidth in bytes (None = unlimited)
    pub max_daily_bandwidth: Option<u64>,
    /// Bytes used today
    pub daily_bandwidth_used: u64,
    /// When daily counter resets (24 hours from creation)
    pub daily_reset_at: SystemTime,
    /// Whether connection is metered (cellular, etc.)
    pub is_metered: bool,
    /// Battery constraints (None if not battery powered)
    pub battery: Option<BatteryConstraints>,
    /// Time-based restriction windows
    pub time_windows: Vec<TimeWindow>,
}

impl ResourceConstraints {
    /// Creates constraints for unlimited edge (typically servers)
    #[must_use]
    pub fn new_unlimited() -> Self {
        Self {
            max_storage_bytes: None,
            max_daily_bandwidth: None,
            daily_bandwidth_used: 0,
            daily_reset_at: SystemTime::now() + Duration::from_secs(86400),
            is_metered: false,
            battery: None,
            time_windows: Vec::new(),
        }
    }

    /// Creates constraints for mobile device with daily bandwidth limit in MB
    #[must_use]
    pub fn new_mobile(max_daily_mb: u64) -> Self {
        Self {
            max_storage_bytes: None,
            max_daily_bandwidth: Some(max_daily_mb * 1024 * 1024),
            daily_bandwidth_used: 0,
            daily_reset_at: SystemTime::now() + Duration::from_secs(86400),
            is_metered: true,
            battery: Some(BatteryConstraints::new(100, false)),
            time_windows: Vec::new(),
        }
    }

    /// Creates constraints for metered connection with daily bandwidth limit in MB
    #[must_use]
    pub fn new_metered(max_daily_mb: u64) -> Self {
        Self {
            max_storage_bytes: None,
            max_daily_bandwidth: Some(max_daily_mb * 1024 * 1024),
            daily_bandwidth_used: 0,
            daily_reset_at: SystemTime::now() + Duration::from_secs(86400),
            is_metered: true,
            battery: None,
            time_windows: Vec::new(),
        }
    }

    /// Checks if a transfer of given size is allowed
    #[must_use]
    pub const fn can_transfer(&self, bytes: u64) -> bool {
        if let Some(max_bandwidth) = self.max_daily_bandwidth {
            if self.daily_bandwidth_used + bytes > max_bandwidth {
                return false;
            }
        }
        true
    }

    /// Checks if current time is allowed for operations
    #[must_use]
    pub fn is_time_allowed(&self) -> bool {
        if self.time_windows.is_empty() {
            return true;
        }

        let mut has_active_allow = false;
        let mut has_active_block = false;

        for window in &self.time_windows {
            if window.is_active_now() {
                if window.allow {
                    has_active_allow = true;
                } else {
                    has_active_block = true;
                }
            }
        }

        if has_active_block {
            return false;
        }

        if has_active_allow {
            return true;
        }

        let has_any_allow = self.time_windows.iter().any(|w| w.allow);
        !has_any_allow
    }

    /// Returns remaining daily bandwidth in bytes
    #[must_use]
    pub fn daily_remaining(&self) -> Option<u64> {
        self.max_daily_bandwidth
            .map(|max| max.saturating_sub(self.daily_bandwidth_used))
    }

    /// Checks if daily bandwidth counter should be reset
    #[must_use]
    pub fn should_reset_daily(&self) -> bool {
        SystemTime::now() >= self.daily_reset_at
    }

    /// Resets daily bandwidth counter and updates reset time
    pub fn reset_daily(&mut self) {
        self.daily_bandwidth_used = 0;
        self.daily_reset_at = SystemTime::now() + Duration::from_secs(86400);
    }
}

/// Per-edge constraint tracker
///
/// Thread-safe manager for resource constraints across all edge devices.
/// Uses `DashMap` for concurrent access without locks.
pub struct ConstraintTracker {
    constraints: DashMap<EdgeId, ResourceConstraints>,
}

impl ConstraintTracker {
    /// Creates a new empty constraint tracker
    #[must_use]
    pub fn new() -> Self {
        Self {
            constraints: DashMap::new(),
        }
    }

    /// Sets constraints for an edge
    pub fn set(&self, edge: EdgeId, constraints: ResourceConstraints) {
        self.constraints.insert(edge, constraints);
    }

    /// Updates battery state for an edge
    #[must_use]
    pub fn update_battery(&self, edge: &EdgeId, battery: BatteryConstraints) -> bool {
        if let Some(mut entry) = self.constraints.get_mut(edge) {
            entry.battery = Some(battery);
            true
        } else {
            false
        }
    }

    /// Updates metered connection status for an edge
    #[must_use]
    pub fn update_metered(&self, edge: &EdgeId, is_metered: bool) -> bool {
        if let Some(mut entry) = self.constraints.get_mut(edge) {
            entry.is_metered = is_metered;
            true
        } else {
            false
        }
    }

    /// Checks if an edge can perform an upload of given size
    #[must_use]
    pub fn can_upload(&self, edge: &EdgeId, bytes: u64) -> bool {
        if let Some(entry) = self.constraints.get(edge) {
            if !entry.can_transfer(bytes) {
                return false;
            }
            if !entry.is_time_allowed() {
                return false;
            }
            if let Some(ref battery) = entry.battery {
                return battery.can_upload();
            }
            true
        } else {
            true
        }
    }

    /// Checks if an edge can perform a download of given size
    #[must_use]
    pub fn can_download(&self, edge: &EdgeId, bytes: u64) -> bool {
        if let Some(entry) = self.constraints.get(edge) {
            if !entry.can_transfer(bytes) {
                return false;
            }
            if !entry.is_time_allowed() {
                return false;
            }
            if let Some(ref battery) = entry.battery {
                return battery.can_download();
            }
            true
        } else {
            true
        }
    }

    /// Checks if an edge is available for operations
    #[must_use]
    pub fn is_available(&self, edge: &EdgeId) -> bool {
        if let Some(entry) = self.constraints.get(edge) {
            if !entry.is_time_allowed() {
                return false;
            }
            if let Some(ref battery) = entry.battery {
                return battery.can_download() || battery.can_upload();
            }
            true
        } else {
            true
        }
    }

    /// Gets constraints for an edge
    #[must_use]
    pub fn get(&self, edge: &EdgeId) -> Option<ResourceConstraints> {
        self.constraints.get(edge).map(|entry| entry.clone())
    }

    /// Records a transfer and updates bandwidth usage
    pub fn record_transfer(&self, edge: &EdgeId, bytes: u64) {
        if let Some(mut entry) = self.constraints.get_mut(edge) {
            entry.daily_bandwidth_used = entry.daily_bandwidth_used.saturating_add(bytes);
        }
    }

    /// Resets daily bandwidth for all edges that need it
    pub fn reset_daily_all(&self) {
        for mut entry in self.constraints.iter_mut() {
            if entry.should_reset_daily() {
                entry.reset_daily();
            }
        }
    }

    /// Removes constraints for an edge
    pub fn remove(&self, edge: &EdgeId) {
        self.constraints.remove(edge);
    }
}

impl Default for ConstraintTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_battery_constraints_new() {
        let battery = BatteryConstraints::new(75, false);
        assert_eq!(battery.current_level, 75);
        assert!(!battery.is_charging);
        assert_eq!(battery.min_battery_upload, 20);
        assert_eq!(battery.min_battery_download, 15);
    }

    #[test]
    fn test_battery_constraints_new_clamps_level() {
        let battery = BatteryConstraints::new(150, false);
        assert_eq!(battery.current_level, 100);
    }

    #[test]
    fn test_battery_constraints_can_upload_high_battery() {
        let battery = BatteryConstraints::new(80, false);
        assert!(battery.can_upload());
    }

    #[test]
    fn test_battery_constraints_can_upload_low_battery() {
        let battery = BatteryConstraints::new(10, false);
        assert!(!battery.can_upload());
    }

    #[test]
    fn test_battery_constraints_can_upload_while_charging() {
        let battery = BatteryConstraints::new(10, true);
        assert!(battery.can_upload());
    }

    #[test]
    fn test_battery_constraints_can_upload_at_threshold() {
        let battery = BatteryConstraints::new(20, false);
        assert!(battery.can_upload());
    }

    #[test]
    fn test_battery_constraints_can_download_high_battery() {
        let battery = BatteryConstraints::new(80, false);
        assert!(battery.can_download());
    }

    #[test]
    fn test_battery_constraints_can_download_low_battery() {
        let battery = BatteryConstraints::new(10, false);
        assert!(!battery.can_download());
    }

    #[test]
    fn test_battery_constraints_can_download_while_charging() {
        let battery = BatteryConstraints::new(5, true);
        assert!(battery.can_download());
    }

    #[test]
    fn test_battery_constraints_can_download_at_threshold() {
        let battery = BatteryConstraints::new(15, false);
        assert!(battery.can_download());
    }

    #[test]
    fn test_time_window_new() {
        let window = TimeWindow::new(1, 9, 17, true);
        assert_eq!(window.day_of_week, 1);
        assert_eq!(window.start_hour, 9);
        assert_eq!(window.end_hour, 17);
        assert!(window.allow);
    }

    #[test]
    fn test_time_window_new_clamps_values() {
        let window = TimeWindow::new(10, 25, 30, false);
        assert_eq!(window.day_of_week, 6);
        assert_eq!(window.start_hour, 23);
        assert_eq!(window.end_hour, 23);
    }

    #[test]
    fn test_time_window_is_active_now() {
        use chrono::prelude::*;

        let now = Local::now();
        let current_day = now.weekday().num_days_from_sunday() as u8;
        let current_hour = now.hour() as u8;

        let active_window = TimeWindow::new(current_day, current_hour, current_hour, true);
        assert!(active_window.is_active_now());

        let different_day = (current_day + 1) % 7;
        let inactive_window = TimeWindow::new(different_day, current_hour, current_hour, true);
        assert!(!inactive_window.is_active_now());
    }

    #[test]
    fn test_resource_constraints_new_unlimited() {
        let unlimited = ResourceConstraints::new_unlimited();
        assert!(unlimited.max_daily_bandwidth.is_none());
        assert!(!unlimited.is_metered);
        assert!(unlimited.battery.is_none());
        assert!(unlimited.time_windows.is_empty());
        assert_eq!(unlimited.daily_bandwidth_used, 0);
    }

    #[test]
    fn test_resource_constraints_new_mobile() {
        let mobile = ResourceConstraints::new_mobile(100);
        assert_eq!(mobile.max_daily_bandwidth, Some(100 * 1024 * 1024));
        assert!(mobile.is_metered);
        assert!(mobile.battery.is_some());
        assert_eq!(mobile.daily_bandwidth_used, 0);
    }

    #[test]
    fn test_resource_constraints_new_metered() {
        let metered = ResourceConstraints::new_metered(500);
        assert_eq!(metered.max_daily_bandwidth, Some(500 * 1024 * 1024));
        assert!(metered.is_metered);
        assert!(metered.battery.is_none());
        assert_eq!(metered.daily_bandwidth_used, 0);
    }

    #[test]
    fn test_resource_constraints_can_transfer_unlimited() {
        let unlimited = ResourceConstraints::new_unlimited();
        assert!(unlimited.can_transfer(1_000_000_000_000));
    }

    #[test]
    fn test_resource_constraints_can_transfer_within_limit() {
        let mobile = ResourceConstraints::new_mobile(100);
        assert!(mobile.can_transfer(50_000_000));
    }

    #[test]
    fn test_resource_constraints_can_transfer_exceeds_limit() {
        let mut mobile = ResourceConstraints::new_mobile(100);
        mobile.daily_bandwidth_used = 100 * 1024 * 1024;
        assert!(!mobile.can_transfer(1000));
    }

    #[test]
    fn test_resource_constraints_is_time_allowed_no_windows() {
        let unlimited = ResourceConstraints::new_unlimited();
        assert!(unlimited.is_time_allowed());
    }

    #[test]
    fn test_resource_constraints_daily_remaining_unlimited() {
        let unlimited = ResourceConstraints::new_unlimited();
        assert_eq!(unlimited.daily_remaining(), None);
    }

    #[test]
    fn test_resource_constraints_daily_remaining_with_limit() {
        let mut mobile = ResourceConstraints::new_mobile(100);
        mobile.daily_bandwidth_used = 50 * 1024 * 1024;
        assert_eq!(mobile.daily_remaining(), Some(50 * 1024 * 1024));
    }

    #[test]
    fn test_resource_constraints_daily_remaining_exceeded() {
        let mut mobile = ResourceConstraints::new_mobile(100);
        mobile.daily_bandwidth_used = 150 * 1024 * 1024;
        assert_eq!(mobile.daily_remaining(), Some(0));
    }

    #[test]
    fn test_resource_constraints_should_reset_daily() {
        let mobile = ResourceConstraints::new_mobile(100);
        assert!(!mobile.should_reset_daily());
    }

    #[test]
    fn test_resource_constraints_reset_daily() {
        let mut mobile = ResourceConstraints::new_mobile(100);
        mobile.daily_bandwidth_used = 50_000_000;
        mobile.reset_daily();
        assert_eq!(mobile.daily_bandwidth_used, 0);
    }

    #[test]
    fn test_constraint_tracker_new() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        assert!(tracker.get(&edge).is_none());
    }

    #[test]
    fn test_constraint_tracker_set_and_get() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mobile = ResourceConstraints::new_mobile(100);

        tracker.set(edge, mobile);
        let retrieved = tracker.get(&edge);
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.unwrap().max_daily_bandwidth,
            Some(100 * 1024 * 1024)
        );
    }

    #[test]
    fn test_constraint_tracker_update_battery_success() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mobile = ResourceConstraints::new_mobile(100);
        tracker.set(edge, mobile);

        let battery = BatteryConstraints::new(50, true);
        assert!(tracker.update_battery(&edge, battery.clone()));

        let constraints = tracker.get(&edge).unwrap();
        assert_eq!(constraints.battery.unwrap().current_level, 50);
    }

    #[test]
    fn test_constraint_tracker_update_battery_not_found() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let battery = BatteryConstraints::new(50, true);

        assert!(!tracker.update_battery(&edge, battery));
    }

    #[test]
    fn test_constraint_tracker_update_metered_success() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let unlimited = ResourceConstraints::new_unlimited();
        tracker.set(edge, unlimited);

        assert!(tracker.update_metered(&edge, true));
        let constraints = tracker.get(&edge).unwrap();
        assert!(constraints.is_metered);
    }

    #[test]
    fn test_constraint_tracker_update_metered_not_found() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);

        assert!(!tracker.update_metered(&edge, true));
    }

    #[test]
    fn test_constraint_tracker_can_upload_no_constraints() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);

        assert!(tracker.can_upload(&edge, 1_000_000_000));
    }

    #[test]
    fn test_constraint_tracker_can_upload_within_limits() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mobile = ResourceConstraints::new_mobile(100);
        tracker.set(edge, mobile);

        assert!(tracker.can_upload(&edge, 10_000_000));
    }

    #[test]
    fn test_constraint_tracker_can_upload_low_battery() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mut mobile = ResourceConstraints::new_mobile(100);
        mobile.battery = Some(BatteryConstraints::new(10, false));
        tracker.set(edge, mobile);

        assert!(!tracker.can_upload(&edge, 10_000_000));
    }

    #[test]
    fn test_constraint_tracker_can_download_no_constraints() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);

        assert!(tracker.can_download(&edge, 1_000_000_000));
    }

    #[test]
    fn test_constraint_tracker_can_download_within_limits() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mobile = ResourceConstraints::new_mobile(100);
        tracker.set(edge, mobile);

        assert!(tracker.can_download(&edge, 10_000_000));
    }

    #[test]
    fn test_constraint_tracker_can_download_low_battery() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mut mobile = ResourceConstraints::new_mobile(100);
        mobile.battery = Some(BatteryConstraints::new(10, false));
        tracker.set(edge, mobile);

        assert!(!tracker.can_download(&edge, 10_000_000));
    }

    #[test]
    fn test_constraint_tracker_is_available_no_constraints() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);

        assert!(tracker.is_available(&edge));
    }

    #[test]
    fn test_constraint_tracker_is_available_with_constraints() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let unlimited = ResourceConstraints::new_unlimited();
        tracker.set(edge, unlimited);

        assert!(tracker.is_available(&edge));
    }

    #[test]
    fn test_constraint_tracker_is_available_low_battery() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mut mobile = ResourceConstraints::new_mobile(100);
        mobile.battery = Some(BatteryConstraints::new(5, false));
        tracker.set(edge, mobile);

        assert!(!tracker.is_available(&edge));
    }

    #[test]
    fn test_constraint_tracker_record_transfer() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mobile = ResourceConstraints::new_mobile(100);
        tracker.set(edge, mobile);

        tracker.record_transfer(&edge, 10_000_000);
        let constraints = tracker.get(&edge).unwrap();
        assert_eq!(constraints.daily_bandwidth_used, 10_000_000);

        tracker.record_transfer(&edge, 5_000_000);
        let constraints = tracker.get(&edge).unwrap();
        assert_eq!(constraints.daily_bandwidth_used, 15_000_000);
    }

    #[test]
    fn test_constraint_tracker_record_transfer_no_edge() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);

        tracker.record_transfer(&edge, 10_000_000);
    }

    #[test]
    fn test_constraint_tracker_reset_daily_all() {
        let tracker = ConstraintTracker::new();
        let edge1 = EdgeId::new([1u8; 32]);
        let edge2 = EdgeId::new([2u8; 32]);

        let mobile1 = ResourceConstraints::new_mobile(100);
        let mobile2 = ResourceConstraints::new_mobile(200);

        tracker.set(edge1, mobile1);
        tracker.set(edge2, mobile2);

        tracker.record_transfer(&edge1, 50_000_000);
        tracker.record_transfer(&edge2, 100_000_000);

        tracker.reset_daily_all();
    }

    #[test]
    fn test_constraint_tracker_remove() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mobile = ResourceConstraints::new_mobile(100);
        tracker.set(edge, mobile);

        assert!(tracker.get(&edge).is_some());
        tracker.remove(&edge);
        assert!(tracker.get(&edge).is_none());
    }

    #[test]
    fn test_constraint_tracker_default() {
        let tracker = ConstraintTracker::default();
        let edge = EdgeId::new([1u8; 32]);
        assert!(tracker.get(&edge).is_none());
    }

    #[test]
    fn test_battery_constraints_serialize() {
        let battery = BatteryConstraints::new(75, true);
        let json = serde_json::to_string(&battery).unwrap();
        let deserialized: BatteryConstraints = serde_json::from_str(&json).unwrap();
        assert_eq!(battery, deserialized);
    }

    #[test]
    fn test_time_window_serialize() {
        let window = TimeWindow::new(1, 9, 17, true);
        let json = serde_json::to_string(&window).unwrap();
        let deserialized: TimeWindow = serde_json::from_str(&json).unwrap();
        assert_eq!(window, deserialized);
    }

    #[test]
    fn test_resource_constraints_serialize() {
        let mobile = ResourceConstraints::new_mobile(100);
        let json = serde_json::to_string(&mobile).unwrap();
        let deserialized: ResourceConstraints = serde_json::from_str(&json).unwrap();
        assert_eq!(mobile.max_daily_bandwidth, deserialized.max_daily_bandwidth);
    }

    #[test]
    fn test_bandwidth_limit_edge_cases() {
        let mut mobile = ResourceConstraints::new_mobile(100);
        let max_bytes = 100 * 1024 * 1024;

        assert!(mobile.can_transfer(max_bytes));

        mobile.daily_bandwidth_used = max_bytes - 1;
        assert!(mobile.can_transfer(1));
        assert!(!mobile.can_transfer(2));
    }

    #[test]
    fn test_combined_constraints() {
        let tracker = ConstraintTracker::new();
        let edge = EdgeId::new([1u8; 32]);
        let mut mobile = ResourceConstraints::new_mobile(100);
        mobile.battery = Some(BatteryConstraints::new(25, false));
        tracker.set(edge, mobile);

        assert!(tracker.can_upload(&edge, 10_000_000));
        assert!(tracker.can_download(&edge, 10_000_000));

        tracker.record_transfer(&edge, 100 * 1024 * 1024);
        assert!(!tracker.can_upload(&edge, 1000));
        assert!(!tracker.can_download(&edge, 1000));
    }
}
