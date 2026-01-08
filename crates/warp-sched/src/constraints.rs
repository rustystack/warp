//! Time/Cost/Power-Aware Scheduling Constraints
//!
//! Provides constraint-based scheduling for GPU chunk transfers with time windows,
//! cost limits, power constraints, and high-level scheduling policies.

use crate::{CpuCostMatrix, EdgeIdx, SchedError};
use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Time-based scheduling window with hour range, day filter, and timezone offset
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start hour of the window (0-23)
    pub start_hour: u8,
    /// End hour of the window (0-23)
    pub end_hour: u8,
    /// Days of the week when this window is active (empty means all days)
    pub days: Vec<Weekday>,
    /// Timezone offset in hours (-12 to +14)
    pub timezone_offset_hours: i8,
}

impl TimeWindow {
    /// Create a new time window with validation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `start_hour` or `end_hour` is greater than 23
    /// - `timezone_offset_hours` is not in the range -12 to +14
    pub fn new(
        start_hour: u8,
        end_hour: u8,
        days: Vec<Weekday>,
        timezone_offset_hours: i8,
    ) -> Result<Self, SchedError> {
        if start_hour > 23 || end_hour > 23 {
            return Err(SchedError::InvalidConfig("hour must be 0-23".to_string()));
        }
        if !(-12..=14).contains(&timezone_offset_hours) {
            return Err(SchedError::InvalidConfig(
                "timezone_offset must be -12 to +14".to_string(),
            ));
        }
        Ok(Self {
            start_hour,
            end_hour,
            days,
            timezone_offset_hours,
        })
    }

    /// Check if the given time falls within this window
    #[must_use]
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        let offset_secs = i64::from(self.timezone_offset_hours) * 3600;
        let local_dt = DateTime::from_timestamp(now.timestamp() + offset_secs, 0).unwrap_or(now);
        if !self.days.is_empty() && !self.days.contains(&local_dt.weekday()) {
            return false;
        }
        let hour = local_dt.hour() as u8;
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour <= self.end_hour
        } else {
            hour >= self.start_hour || hour <= self.end_hour
        }
    }

    /// Create an all-day window
    ///
    /// # Errors
    ///
    /// Returns an error if `timezone_offset_hours` is not in the range -12 to +14
    pub fn all_day(days: Vec<Weekday>, timezone_offset_hours: i8) -> Result<Self, SchedError> {
        Self::new(0, 23, days, timezone_offset_hours)
    }

    /// Create a 24/7 always-active window
    #[must_use]
    pub const fn always() -> Self {
        Self {
            start_hour: 0,
            end_hour: 23,
            days: vec![],
            timezone_offset_hours: 0,
        }
    }
}

/// Time-based constraint types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeConstraint {
    /// No time restrictions
    Anytime,
    /// Prefer this window but don't require it
    PreferredWindow(TimeWindow),
    /// Must be within this window
    RequiredWindow(TimeWindow),
    /// Avoid this window if possible
    AvoidWindow(TimeWindow),
    /// Avoid peak hours (specified as list of hours 0-23)
    OffPeak {
        /// List of peak hours (0-23) to avoid
        peak_hours: Vec<u8>,
    },
}

impl TimeConstraint {
    /// Check if time constraint allows transfers now
    #[must_use]
    pub fn is_allowed(&self, now: DateTime<Utc>) -> bool {
        match self {
            Self::Anytime => true,
            Self::PreferredWindow(_) => true,
            Self::RequiredWindow(window) => window.is_active(now),
            Self::AvoidWindow(window) => !window.is_active(now),
            Self::OffPeak { peak_hours } => {
                let hour = now.hour() as u8;
                !peak_hours.contains(&hour)
            }
        }
    }

    /// Get cost multiplier based on preference (1.0 = normal, higher = less preferred)
    #[must_use]
    pub fn cost_multiplier(&self, now: DateTime<Utc>) -> f64 {
        match self {
            Self::Anytime => 1.0,
            Self::PreferredWindow(window) => {
                if window.is_active(now) {
                    0.8 // Prefer this window
                } else {
                    1.2 // Less preferred outside window
                }
            }
            Self::RequiredWindow(window) => {
                if window.is_active(now) {
                    1.0
                } else {
                    f64::INFINITY // Block outside window
                }
            }
            Self::AvoidWindow(window) => {
                if window.is_active(now) {
                    5.0 // Strongly avoid
                } else {
                    1.0
                }
            }
            Self::OffPeak { peak_hours } => {
                let hour = now.hour() as u8;
                if peak_hours.contains(&hour) {
                    2.0 // Avoid peak hours
                } else {
                    0.9 // Prefer off-peak
                }
            }
        }
    }
}

/// Cost constraint types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CostConstraint {
    /// No cost concerns
    Unlimited,
    /// Metered connection with bytes remaining
    MeteredLimit {
        /// Number of bytes remaining in the limit
        bytes_remaining: u64,
    },
    /// Monthly budget with used and limit
    MonthlyBudget {
        /// Number of bytes already used
        used: u64,
        /// Total byte limit for the month
        limit: u64,
    },
    /// Prefer unmetered but allow metered
    PreferUnmetered,
    /// Only use unmetered connections
    UnmeteredOnly,
}

impl CostConstraint {
    /// Check if transfer of given size is allowed
    #[must_use]
    pub fn is_allowed(&self, bytes: u64) -> bool {
        match self {
            Self::Unlimited => true,
            Self::MeteredLimit { bytes_remaining } => bytes <= *bytes_remaining,
            Self::MonthlyBudget { used, limit } => used + bytes <= *limit,
            Self::PreferUnmetered => true,
            Self::UnmeteredOnly => false, // Assumes edge is metered
        }
    }

    /// Get cost multiplier (1.0 = normal, higher = more expensive)
    #[must_use]
    pub fn cost_multiplier(&self, bytes: u64) -> f64 {
        match self {
            Self::Unlimited => 1.0,
            Self::MeteredLimit { bytes_remaining } => {
                if bytes > *bytes_remaining {
                    f64::INFINITY
                } else {
                    let ratio = bytes as f64 / (*bytes_remaining as f64).max(1.0);
                    1.0 + ratio // Cost increases as budget depletes
                }
            }
            Self::MonthlyBudget { used, limit } => {
                if used + bytes > *limit {
                    f64::INFINITY
                } else {
                    let ratio = (*used as f64) / (*limit as f64).max(1.0);
                    1.0 + ratio * 2.0 // Cost increases with budget usage
                }
            }
            Self::PreferUnmetered => 1.5,         // Prefer unmetered
            Self::UnmeteredOnly => f64::INFINITY, // Block metered
        }
    }
}

/// Power constraint types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerConstraint {
    /// No power concerns
    Unlimited,
    /// Only when plugged into AC power
    PluggedInOnly,
    /// Minimum battery level required (0-100)
    MinBattery {
        /// Minimum battery percentage required (0-100)
        percent: u8,
    },
    /// Low power mode (reduce activity)
    LowPowerMode,
    /// Only during charging windows
    Scheduled {
        /// Time windows when charging is allowed
        charge_windows: Vec<TimeWindow>,
    },
}

impl PowerConstraint {
    /// Check if constraint allows transfers
    #[must_use]
    pub fn is_allowed(
        &self,
        battery_level: Option<u8>,
        is_charging: bool,
        now: DateTime<Utc>,
    ) -> bool {
        match self {
            Self::Unlimited => true,
            Self::PluggedInOnly => is_charging,
            Self::MinBattery { percent } => {
                is_charging || battery_level.is_none_or(|l| l >= *percent)
            }
            Self::LowPowerMode => is_charging || battery_level.is_none_or(|l| l >= 50),
            Self::Scheduled { charge_windows } => charge_windows.iter().any(|w| w.is_active(now)),
        }
    }

    /// Get cost multiplier
    #[must_use]
    pub fn cost_multiplier(
        &self,
        battery_level: Option<u8>,
        is_charging: bool,
        now: DateTime<Utc>,
    ) -> f64 {
        match self {
            Self::Unlimited => 1.0,
            Self::PluggedInOnly => {
                if is_charging {
                    1.0
                } else {
                    f64::INFINITY
                }
            }
            Self::MinBattery { percent } => {
                if is_charging {
                    return 0.9; // Prefer when charging
                }
                if let Some(level) = battery_level {
                    if level < *percent {
                        f64::INFINITY
                    } else {
                        let safety_margin = f64::from(level.saturating_sub(*percent)) / 100.0;
                        1.0 + (1.0 - safety_margin) // Higher cost as battery approaches min
                    }
                } else {
                    1.0 // Unknown battery level, allow
                }
            }
            Self::LowPowerMode => {
                if is_charging {
                    1.0
                } else if let Some(level) = battery_level {
                    if level < 50 {
                        3.0 // High cost in low power
                    } else {
                        1.2
                    }
                } else {
                    1.2
                }
            }
            Self::Scheduled { charge_windows } => {
                if charge_windows.iter().any(|w| w.is_active(now)) {
                    1.0
                } else {
                    f64::INFINITY
                }
            }
        }
    }
}

/// Complete constraints for a specific edge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeConstraints {
    /// The edge index this constraint applies to
    pub edge_idx: EdgeIdx,
    /// Time-based constraint for this edge
    pub time: TimeConstraint,
    /// Cost-based constraint for this edge
    pub cost: CostConstraint,
    /// Power-based constraint for this edge
    pub power: PowerConstraint,
    /// Maximum number of concurrent transfers allowed on this edge
    pub max_concurrent_transfers: Option<usize>,
    /// Bandwidth limit in bits per second for this edge
    pub bandwidth_limit_bps: Option<u64>,
}

impl EdgeConstraints {
    /// Create new edge constraints with all constraints set to unlimited
    #[must_use]
    pub const fn new(edge_idx: EdgeIdx) -> Self {
        Self {
            edge_idx,
            time: TimeConstraint::Anytime,
            cost: CostConstraint::Unlimited,
            power: PowerConstraint::Unlimited,
            max_concurrent_transfers: None,
            bandwidth_limit_bps: None,
        }
    }

    /// Set the time constraint for this edge
    #[must_use]
    pub fn with_time(mut self, time: TimeConstraint) -> Self {
        self.time = time;
        self
    }

    /// Set the cost constraint for this edge
    #[must_use]
    pub const fn with_cost(mut self, cost: CostConstraint) -> Self {
        self.cost = cost;
        self
    }

    /// Set the power constraint for this edge
    #[must_use]
    pub fn with_power(mut self, power: PowerConstraint) -> Self {
        self.power = power;
        self
    }

    /// Set the maximum concurrent transfers for this edge
    #[must_use]
    pub const fn with_max_transfers(mut self, max: usize) -> Self {
        self.max_concurrent_transfers = Some(max);
        self
    }

    /// Set the bandwidth limit in bits per second for this edge
    #[must_use]
    pub const fn with_bandwidth_limit(mut self, bps: u64) -> Self {
        self.bandwidth_limit_bps = Some(bps);
        self
    }
}

/// Severity of constraint violation (Soft = warning, Hard = blocking)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ViolationSeverity {
    /// Soft violation (warning only, does not block)
    Soft,
    /// Hard violation (blocks the operation)
    Hard,
}

/// Details of a constraint violation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintViolation {
    /// The edge where the violation occurred
    pub edge_idx: EdgeIdx,
    /// The type of constraint that was violated
    pub constraint_type: String,
    /// The severity of this violation
    pub severity: ViolationSeverity,
    /// Human-readable message describing the violation
    pub message: String,
}

impl ConstraintViolation {
    /// Create a new constraint violation
    pub fn new(
        edge_idx: EdgeIdx,
        constraint_type: impl Into<String>,
        severity: ViolationSeverity,
        message: impl Into<String>,
    ) -> Self {
        Self {
            edge_idx,
            constraint_type: constraint_type.into(),
            severity,
            message: message.into(),
        }
    }
}

/// Evaluates constraints for edges
pub struct ConstraintEvaluator {
    /// Map of edge constraints by edge index
    constraints: HashMap<EdgeIdx, EdgeConstraints>,
    /// Map of battery levels by edge index (0-100)
    battery_levels: HashMap<EdgeIdx, u8>,
    /// Map of charging states by edge index
    charging_states: HashMap<EdgeIdx, bool>,
}

impl ConstraintEvaluator {
    /// Create a new constraint evaluator with no constraints
    #[must_use]
    pub fn new() -> Self {
        Self {
            constraints: HashMap::new(),
            battery_levels: HashMap::new(),
            charging_states: HashMap::new(),
        }
    }

    /// Add or update constraints for an edge
    pub fn add_constraint(&mut self, edge_idx: EdgeIdx, constraints: EdgeConstraints) {
        self.constraints.insert(edge_idx, constraints);
    }

    /// Remove all constraints and state for an edge
    pub fn remove_constraint(&mut self, edge_idx: EdgeIdx) {
        self.constraints.remove(&edge_idx);
        self.battery_levels.remove(&edge_idx);
        self.charging_states.remove(&edge_idx);
    }

    /// Update battery level and charging state for an edge
    pub fn update_battery(&mut self, edge_idx: EdgeIdx, level: u8, is_charging: bool) {
        self.battery_levels.insert(edge_idx, level);
        self.charging_states.insert(edge_idx, is_charging);
    }

    /// Check if edge is available for transfers now
    #[must_use]
    pub fn is_available(&self, edge_idx: EdgeIdx, now: DateTime<Utc>) -> bool {
        if let Some(constraints) = self.constraints.get(&edge_idx) {
            let battery = self.battery_levels.get(&edge_idx).copied();
            let charging = self
                .charging_states
                .get(&edge_idx)
                .copied()
                .unwrap_or(false);

            constraints.time.is_allowed(now) && constraints.power.is_allowed(battery, charging, now)
        } else {
            true // No constraints means available
        }
    }

    /// Get cost multiplier for an edge
    #[must_use]
    pub fn cost_multiplier(&self, edge_idx: EdgeIdx, now: DateTime<Utc>, bytes: u64) -> f64 {
        if let Some(constraints) = self.constraints.get(&edge_idx) {
            let battery = self.battery_levels.get(&edge_idx).copied();
            let charging = self
                .charging_states
                .get(&edge_idx)
                .copied()
                .unwrap_or(false);

            let time_mult = constraints.time.cost_multiplier(now);
            let cost_mult = constraints.cost.cost_multiplier(bytes);
            let power_mult = constraints.power.cost_multiplier(battery, charging, now);

            // Multiply all factors
            time_mult * cost_mult * power_mult
        } else {
            1.0 // No constraints
        }
    }

    /// Get list of available edges from candidates
    #[must_use]
    pub fn get_available_edges(&self, edges: &[EdgeIdx], now: DateTime<Utc>) -> Vec<EdgeIdx> {
        edges
            .iter()
            .copied()
            .filter(|&edge_idx| self.is_available(edge_idx, now))
            .collect()
    }

    /// Apply constraints to cost matrix
    ///
    /// Modifies costs in-place based on time, cost, and power constraints.
    /// Edges that are blocked by constraints are invalidated.
    pub fn apply_to_cost_matrix(&self, costs: &mut CpuCostMatrix, now: DateTime<Utc>) {
        let (num_chunks, num_edges) = costs.dimensions();

        for chunk_idx in 0..num_chunks {
            for edge_idx in 0..num_edges {
                let edge = EdgeIdx::new(edge_idx as u32);

                // First check if edge is available at all
                if !self.is_available(edge, now) {
                    // Edge is blocked by hard constraints - invalidate
                    costs.invalidate(chunk_idx, edge_idx);
                    continue;
                }

                // Assume average chunk size for multiplier calculation
                let multiplier = self.cost_multiplier(edge, now, 1_000_000);

                // Get current cost if valid
                if let Some(current_cost) =
                    costs.get_cost(crate::ChunkId::new(chunk_idx as u64), edge)
                {
                    if multiplier.is_infinite() {
                        // Infinite multiplier means blocked
                        costs.invalidate(chunk_idx, edge_idx);
                    } else {
                        // Apply multiplier to adjust cost
                        let new_cost = (f64::from(current_cost) * multiplier) as f32;
                        costs.set_cost(chunk_idx, edge_idx, new_cost);
                    }
                }
            }
        }
    }
}

impl Default for ConstraintEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level scheduling policies
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SchedulePolicy {
    /// Maximize speed, ignore cost/power
    Performance,
    /// Balance speed with cost/power
    Balanced,
    /// Minimize power usage
    EcoFriendly,
    /// Minimize data costs
    CostConscious,
    /// Reduce activity during quiet hours
    Quiet {
        /// Time window defining quiet hours
        hours: TimeWindow,
    },
    /// Custom weights
    Custom {
        /// Weight for time constraints (0.0-1.0)
        time_weight: f64,
        /// Weight for cost constraints (0.0-1.0)
        cost_weight: f64,
        /// Weight for power constraints (0.0-1.0)
        power_weight: f64,
    },
}

impl SchedulePolicy {
    /// Get time weight for this policy
    #[must_use]
    pub const fn time_weight(&self) -> f64 {
        match self {
            Self::Performance => 0.1,
            Self::Balanced => 0.3,
            Self::EcoFriendly => 0.2,
            Self::CostConscious => 0.2,
            Self::Quiet { .. } => 0.5,
            Self::Custom { time_weight, .. } => *time_weight,
        }
    }

    /// Get cost weight for this policy
    #[must_use]
    pub const fn cost_weight(&self) -> f64 {
        match self {
            Self::Performance => 0.1,
            Self::Balanced => 0.3,
            Self::EcoFriendly => 0.2,
            Self::CostConscious => 0.6,
            Self::Quiet { .. } => 0.2,
            Self::Custom { cost_weight, .. } => *cost_weight,
        }
    }

    /// Get power weight for this policy
    #[must_use]
    pub const fn power_weight(&self) -> f64 {
        match self {
            Self::Performance => 0.1,
            Self::Balanced => 0.3,
            Self::EcoFriendly => 0.6,
            Self::CostConscious => 0.2,
            Self::Quiet { .. } => 0.3,
            Self::Custom { power_weight, .. } => *power_weight,
        }
    }
}

/// Policy-based scheduling engine
pub struct PolicyEngine {
    /// The active scheduling policy
    policy: SchedulePolicy,
}

impl PolicyEngine {
    /// Create a new policy engine with the given scheduling policy
    #[must_use]
    pub const fn new(policy: SchedulePolicy) -> Self {
        Self { policy }
    }

    /// Update the active scheduling policy
    pub fn set_policy(&mut self, policy: SchedulePolicy) {
        self.policy = policy;
    }

    /// Get a reference to the active scheduling policy
    #[must_use]
    pub const fn policy(&self) -> &SchedulePolicy {
        &self.policy
    }

    /// Adjust costs based on policy
    pub const fn adjust_costs(
        &self,
        _costs: &mut CpuCostMatrix,
        _constraints: &ConstraintEvaluator,
        _now: DateTime<Utc>,
    ) {
        // Apply policy-specific adjustments to cost matrix
        // This would scale costs based on policy weights
        // Implementation depends on CpuCostMatrix providing set_cost method
    }

    /// Filter edges based on policy and constraints
    #[must_use]
    pub fn filter_edges(
        &self,
        edges: &[EdgeIdx],
        constraints: &ConstraintEvaluator,
        now: DateTime<Utc>,
    ) -> Vec<EdgeIdx> {
        match &self.policy {
            SchedulePolicy::Quiet { hours } => {
                if hours.is_active(now) {
                    // During quiet hours, only use edges that are available
                    constraints.get_available_edges(edges, now)
                } else {
                    edges.to_vec()
                }
            }
            _ => constraints.get_available_edges(edges, now),
        }
    }

    /// Determine if transfers should be paused
    #[must_use]
    pub fn should_pause_transfers(
        &self,
        _constraints: &ConstraintEvaluator,
        now: DateTime<Utc>,
    ) -> bool {
        match &self.policy {
            SchedulePolicy::Quiet { hours } => hours.is_active(now),
            _ => false,
        }
    }

    /// Get transfer priority level (0-255)
    #[must_use]
    pub const fn get_transfer_priority(&self) -> u8 {
        match self.policy {
            SchedulePolicy::Performance => 255,
            SchedulePolicy::Balanced => 128,
            SchedulePolicy::EcoFriendly => 64,
            SchedulePolicy::CostConscious => 96,
            SchedulePolicy::Quiet { .. } => 32,
            SchedulePolicy::Custom { .. } => 128,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_window_creation_and_validation() {
        // Valid creation
        let window = TimeWindow::new(9, 17, vec![Weekday::Mon], 0).unwrap();
        assert_eq!(window.start_hour, 9);
        assert_eq!(window.end_hour, 17);
        assert_eq!(window.days, vec![Weekday::Mon]);
        assert_eq!(window.timezone_offset_hours, 0);

        // Invalid inputs
        assert!(TimeWindow::new(24, 17, vec![Weekday::Mon], 0).is_err());
        assert!(TimeWindow::new(9, 25, vec![Weekday::Mon], 0).is_err());
        assert!(TimeWindow::new(9, 17, vec![Weekday::Mon], 15).is_err());
    }

    #[test]
    fn test_time_window_is_active() {
        // Simple range
        let window = TimeWindow::new(10, 14, vec![], 0).unwrap();
        let time_12 = DateTime::from_timestamp(1704196800, 0).unwrap();
        let time_08 = DateTime::from_timestamp(1704182400, 0).unwrap();
        assert!(window.is_active(time_12));
        assert!(!window.is_active(time_08));

        // Wrap-around (22:00-02:00)
        let wrap = TimeWindow::new(22, 2, vec![], 0).unwrap();
        let time_23 = DateTime::from_timestamp(1704236400, 0).unwrap();
        let time_01 = DateTime::from_timestamp(1704157200, 0).unwrap();
        assert!(wrap.is_active(time_23));
        assert!(wrap.is_active(time_01));
        assert!(!wrap.is_active(time_12));

        // Day filter
        let day_win = TimeWindow::new(0, 23, vec![Weekday::Mon], 0).unwrap();
        let monday = DateTime::from_timestamp(1704067200, 0).unwrap();
        let tuesday = DateTime::from_timestamp(1704153600, 0).unwrap();
        assert!(day_win.is_active(monday));
        assert!(!day_win.is_active(tuesday));

        // Timezone offset
        let tz_win = TimeWindow::new(10, 14, vec![], -5).unwrap();
        let utc_15 = DateTime::from_timestamp(1704121200, 0).unwrap();
        assert!(tz_win.is_active(utc_15));
    }

    #[test]
    fn test_time_window_helpers() {
        // All day
        let all_day = TimeWindow::all_day(vec![Weekday::Mon, Weekday::Tue], 0).unwrap();
        assert_eq!(all_day.start_hour, 0);
        assert_eq!(all_day.end_hour, 23);

        // Always
        let always = TimeWindow::always();
        assert!(always.is_active(DateTime::from_timestamp(1704110400, 0).unwrap()));
    }

    #[test]
    fn test_time_constraints() {
        let time_12 = DateTime::from_timestamp(1704196800, 0).unwrap();
        let time_08 = DateTime::from_timestamp(1704182400, 0).unwrap();
        let window = TimeWindow::new(10, 14, vec![], 0).unwrap();

        // Anytime
        assert!(TimeConstraint::Anytime.is_allowed(Utc::now()));
        assert_eq!(TimeConstraint::Anytime.cost_multiplier(Utc::now()), 1.0);

        // Preferred window
        let pref = TimeConstraint::PreferredWindow(window.clone());
        assert!(pref.is_allowed(time_08)); // Allowed but not preferred
        assert_eq!(pref.cost_multiplier(time_12), 0.8);
        assert_eq!(pref.cost_multiplier(time_08), 1.2);

        // Required window
        let req = TimeConstraint::RequiredWindow(window.clone());
        assert!(req.is_allowed(time_12));
        assert!(!req.is_allowed(time_08));
        assert_eq!(req.cost_multiplier(time_08), f64::INFINITY);

        // Avoid window
        let avoid = TimeConstraint::AvoidWindow(window);
        assert!(!avoid.is_allowed(time_12));
        assert!(avoid.is_allowed(time_08));
        assert_eq!(avoid.cost_multiplier(time_12), 5.0);

        // Off-peak
        let off_peak = TimeConstraint::OffPeak {
            peak_hours: vec![10, 11, 17, 18],
        };
        let time_10 = DateTime::from_timestamp(1704189600, 0).unwrap();
        let time_14 = DateTime::from_timestamp(1704204000, 0).unwrap();
        assert!(!off_peak.is_allowed(time_10));
        assert!(off_peak.is_allowed(time_14));
    }

    #[test]
    fn test_cost_constraints() {
        // Unlimited
        assert!(CostConstraint::Unlimited.is_allowed(1_000_000_000));
        assert_eq!(
            CostConstraint::Unlimited.cost_multiplier(1_000_000_000),
            1.0
        );

        // Metered limit
        let metered = CostConstraint::MeteredLimit {
            bytes_remaining: 1_000_000_000,
        };
        assert!(metered.is_allowed(500_000_000));
        assert!(metered.cost_multiplier(500_000_000) > 1.0);
        let exceeded = CostConstraint::MeteredLimit {
            bytes_remaining: 100_000_000,
        };
        assert!(!exceeded.is_allowed(200_000_000));

        // Monthly budget
        let budget = CostConstraint::MonthlyBudget {
            used: 500_000_000,
            limit: 1_000_000_000,
        };
        assert!(budget.is_allowed(300_000_000));
        assert!(!budget.is_allowed(600_000_000));

        // Prefer unmetered
        assert!(CostConstraint::PreferUnmetered.is_allowed(1_000_000_000));
        assert_eq!(
            CostConstraint::PreferUnmetered.cost_multiplier(1_000_000_000),
            1.5
        );

        // Unmetered only
        assert!(!CostConstraint::UnmeteredOnly.is_allowed(1_000_000_000));
    }

    #[test]
    fn test_power_constraints() {
        let now = Utc::now();

        // Unlimited
        let unlimited = PowerConstraint::Unlimited;
        assert!(unlimited.is_allowed(Some(50), false, now));
        assert_eq!(unlimited.cost_multiplier(Some(50), false, now), 1.0);

        // Plugged in only
        let plugged = PowerConstraint::PluggedInOnly;
        assert!(plugged.is_allowed(Some(50), true, now));
        assert!(!plugged.is_allowed(Some(50), false, now));
        assert_eq!(plugged.cost_multiplier(Some(50), false, now), f64::INFINITY);

        // Min battery
        let min_bat = PowerConstraint::MinBattery { percent: 30 };
        assert!(min_bat.is_allowed(Some(50), false, now));
        assert!(!min_bat.is_allowed(Some(20), false, now));
        assert!(min_bat.is_allowed(Some(10), true, now)); // Charging overrides
        assert_eq!(min_bat.cost_multiplier(Some(10), true, now), 0.9);

        // Low power mode
        let low_power = PowerConstraint::LowPowerMode;
        assert!(low_power.is_allowed(Some(60), false, now));
        assert!(!low_power.is_allowed(Some(40), false, now));
    }

    #[test]
    fn test_power_constraint_scheduled() {
        let window = TimeWindow::new(10, 14, vec![], 0).unwrap();
        let constraint = PowerConstraint::Scheduled {
            charge_windows: vec![window],
        };

        let time_12 = DateTime::from_timestamp(1704196800, 0).unwrap(); // 2024-01-02 12:00:00 UTC
        let time_08 = DateTime::from_timestamp(1704182400, 0).unwrap(); // 2024-01-02 08:00:00 UTC

        assert!(constraint.is_allowed(None, false, time_12));
        assert!(!constraint.is_allowed(None, false, time_08));
    }

    #[test]
    fn test_edge_constraints_and_violations() {
        // Builder pattern
        let constraints = EdgeConstraints::new(EdgeIdx::new(0))
            .with_time(TimeConstraint::Anytime)
            .with_cost(CostConstraint::Unlimited)
            .with_power(PowerConstraint::Unlimited)
            .with_max_transfers(10)
            .with_bandwidth_limit(1_000_000_000);
        assert_eq!(constraints.edge_idx, EdgeIdx::new(0));
        assert_eq!(constraints.max_concurrent_transfers, Some(10));

        // Violation severity
        assert!(ViolationSeverity::Soft < ViolationSeverity::Hard);

        // Violation creation
        let violation =
            ConstraintViolation::new(EdgeIdx::new(0), "time", ViolationSeverity::Hard, "Test");
        assert_eq!(violation.edge_idx, EdgeIdx::new(0));
        assert_eq!(violation.severity, ViolationSeverity::Hard);
    }

    #[test]
    fn test_constraint_evaluator_basic() {
        let mut evaluator = ConstraintEvaluator::new();
        let now = Utc::now();

        // No constraints means available
        assert!(evaluator.is_available(EdgeIdx::new(0), now));

        // Add and remove
        evaluator.add_constraint(EdgeIdx::new(0), EdgeConstraints::new(EdgeIdx::new(0)));
        assert!(evaluator.constraints.contains_key(&EdgeIdx::new(0)));
        evaluator.remove_constraint(EdgeIdx::new(0));
        assert!(!evaluator.constraints.contains_key(&EdgeIdx::new(0)));
    }

    #[test]
    fn test_constraint_evaluator_availability() {
        let mut evaluator = ConstraintEvaluator::new();
        let time_12 = DateTime::from_timestamp(1704196800, 0).unwrap();
        let time_08 = DateTime::from_timestamp(1704182400, 0).unwrap();

        // Time constraints
        let window = TimeWindow::new(10, 14, vec![], 0).unwrap();
        let time_con =
            EdgeConstraints::new(EdgeIdx::new(0)).with_time(TimeConstraint::RequiredWindow(window));
        evaluator.add_constraint(EdgeIdx::new(0), time_con);
        assert!(evaluator.is_available(EdgeIdx::new(0), time_12));
        assert!(!evaluator.is_available(EdgeIdx::new(0), time_08));

        // Power constraints
        let power_con = EdgeConstraints::new(EdgeIdx::new(1))
            .with_power(PowerConstraint::MinBattery { percent: 30 });
        evaluator.add_constraint(EdgeIdx::new(1), power_con);
        evaluator.update_battery(EdgeIdx::new(1), 50, false);
        assert!(evaluator.is_available(EdgeIdx::new(1), Utc::now()));
        evaluator.update_battery(EdgeIdx::new(1), 20, false);
        assert!(!evaluator.is_available(EdgeIdx::new(1), Utc::now()));

        // Cost multiplier
        let win2 = TimeWindow::new(10, 14, vec![], 0).unwrap();
        let cost_con =
            EdgeConstraints::new(EdgeIdx::new(2)).with_time(TimeConstraint::PreferredWindow(win2));
        evaluator.add_constraint(EdgeIdx::new(2), cost_con);
        assert_eq!(
            evaluator.cost_multiplier(EdgeIdx::new(2), time_12, 1_000_000),
            0.8
        );
    }

    #[test]
    fn test_constraint_evaluator_get_available_edges() {
        let mut evaluator = ConstraintEvaluator::new();
        let window = TimeWindow::new(10, 14, vec![], 0).unwrap();

        let constraints0 = EdgeConstraints::new(EdgeIdx::new(0))
            .with_time(TimeConstraint::RequiredWindow(window.clone()));
        let constraints1 =
            EdgeConstraints::new(EdgeIdx::new(1)).with_time(TimeConstraint::RequiredWindow(window));

        evaluator.add_constraint(EdgeIdx::new(0), constraints0);
        evaluator.add_constraint(EdgeIdx::new(1), constraints1);

        let edges = vec![EdgeIdx::new(0), EdgeIdx::new(1), EdgeIdx::new(2)];

        let time_12 = DateTime::from_timestamp(1704196800, 0).unwrap(); // 2024-01-02 12:00:00 UTC
        let available = evaluator.get_available_edges(&edges, time_12);
        assert_eq!(available.len(), 3); // All available during window

        let time_08 = DateTime::from_timestamp(1704182400, 0).unwrap(); // 2024-01-02 08:00:00 UTC
        let available = evaluator.get_available_edges(&edges, time_08);
        assert_eq!(available.len(), 1); // Only edge 2 (no constraints)
    }

    #[test]
    fn test_schedule_policies() {
        // Performance
        let perf = SchedulePolicy::Performance;
        assert_eq!(perf.time_weight(), 0.1);
        assert_eq!(perf.cost_weight(), 0.1);

        // Balanced
        let bal = SchedulePolicy::Balanced;
        assert_eq!(bal.time_weight(), 0.3);
        assert_eq!(bal.cost_weight(), 0.3);

        // Eco-friendly
        assert_eq!(SchedulePolicy::EcoFriendly.power_weight(), 0.6);

        // Cost-conscious
        assert_eq!(SchedulePolicy::CostConscious.cost_weight(), 0.6);

        // Custom
        let custom = SchedulePolicy::Custom {
            time_weight: 0.5,
            cost_weight: 0.3,
            power_weight: 0.2,
        };
        assert_eq!(custom.time_weight(), 0.5);
    }

    #[test]
    fn test_policy_engine_basic() {
        let mut engine = PolicyEngine::new(SchedulePolicy::Performance);
        assert_eq!(engine.policy(), &SchedulePolicy::Performance);

        engine.set_policy(SchedulePolicy::EcoFriendly);
        assert_eq!(engine.policy(), &SchedulePolicy::EcoFriendly);
    }

    #[test]
    fn test_policy_engine_filter_edges() {
        let engine = PolicyEngine::new(SchedulePolicy::Performance);
        let mut evaluator = ConstraintEvaluator::new();

        let window = TimeWindow::new(10, 14, vec![], 0).unwrap();
        let constraints =
            EdgeConstraints::new(EdgeIdx::new(0)).with_time(TimeConstraint::RequiredWindow(window));

        evaluator.add_constraint(EdgeIdx::new(0), constraints);

        let edges = vec![EdgeIdx::new(0), EdgeIdx::new(1)];
        let time_08 = DateTime::from_timestamp(1704182400, 0).unwrap(); // 2024-01-02 08:00:00 UTC

        let filtered = engine.filter_edges(&edges, &evaluator, time_08);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], EdgeIdx::new(1));
    }

    #[test]
    fn test_policy_engine_quiet_hours_and_priority() {
        // Quiet hours pause
        let window = TimeWindow::new(22, 6, vec![], 0).unwrap();
        let engine = PolicyEngine::new(SchedulePolicy::Quiet { hours: window });
        let time_23 = DateTime::from_timestamp(1704236400, 0).unwrap();
        let time_12 = DateTime::from_timestamp(1704196800, 0).unwrap();
        assert!(engine.should_pause_transfers(&ConstraintEvaluator::new(), time_23));
        assert!(!engine.should_pause_transfers(&ConstraintEvaluator::new(), time_12));

        // Transfer priorities
        assert_eq!(
            PolicyEngine::new(SchedulePolicy::Performance).get_transfer_priority(),
            255
        );
        assert_eq!(
            PolicyEngine::new(SchedulePolicy::Balanced).get_transfer_priority(),
            128
        );
        assert_eq!(
            PolicyEngine::new(SchedulePolicy::EcoFriendly).get_transfer_priority(),
            64
        );
    }

    #[test]
    fn test_integration_constraints_to_policy() {
        // Integration test: constraints + policy + scheduling
        let mut evaluator = ConstraintEvaluator::new();

        // Edge 0: Work hours only, low battery
        let work_hours = TimeWindow::new(
            9,
            17,
            vec![
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
            ],
            0,
        )
        .unwrap();
        let edge0 = EdgeConstraints::new(EdgeIdx::new(0))
            .with_time(TimeConstraint::RequiredWindow(work_hours))
            .with_power(PowerConstraint::MinBattery { percent: 20 });
        evaluator.add_constraint(EdgeIdx::new(0), edge0);
        evaluator.update_battery(EdgeIdx::new(0), 15, false);

        // Edge 1: Metered connection
        let edge1 = EdgeConstraints::new(EdgeIdx::new(1)).with_cost(CostConstraint::MeteredLimit {
            bytes_remaining: 100_000_000,
        });
        evaluator.add_constraint(EdgeIdx::new(1), edge1);

        // Edge 2: No constraints
        let edge2 = EdgeConstraints::new(EdgeIdx::new(2));
        evaluator.add_constraint(EdgeIdx::new(2), edge2);

        let edges = vec![EdgeIdx::new(0), EdgeIdx::new(1), EdgeIdx::new(2)];

        // During work hours: Monday 12:00 UTC
        let work_time = DateTime::from_timestamp(1704196800, 0).unwrap(); // 2024-01-02 12:00:00 UTC (Tuesday)

        // With cost-conscious policy
        let engine = PolicyEngine::new(SchedulePolicy::CostConscious);
        let available = engine.filter_edges(&edges, &evaluator, work_time);

        // Edge 0: blocked by battery
        // Edge 1: available but expensive (metered)
        // Edge 2: available
        assert!(available.contains(&EdgeIdx::new(1)));
        assert!(available.contains(&EdgeIdx::new(2)));
        assert!(!available.contains(&EdgeIdx::new(0)));
    }
}
