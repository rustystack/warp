//! Shuttle-based concurrency tests for the Scrub scheduler
//!
//! These tests use shuttle to randomly explore interleavings of
//! concurrent operations on the scrub scheduler state machine.

use shuttle::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use shuttle::sync::{Mutex, RwLock};
use shuttle::thread;
use std::sync::Arc;
use std::time::Duration;

/// Simplified scheduler state for shuttle testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScrubState {
    Idle,
    LightScrubbing,
    DeepScrubbing,
    Paused,
}

/// Simplified scrub scheduler for concurrent testing
struct ShuttleScrubScheduler {
    state: RwLock<ScrubState>,
    paused: AtomicBool,
    light_scrub_count: AtomicU64,
    deep_scrub_count: AtomicU64,
    current_load: Mutex<f64>,
    load_threshold: f64,
}

impl ShuttleScrubScheduler {
    fn new(load_threshold: f64) -> Self {
        Self {
            state: RwLock::new(ScrubState::Idle),
            paused: AtomicBool::new(false),
            light_scrub_count: AtomicU64::new(0),
            deep_scrub_count: AtomicU64::new(0),
            current_load: Mutex::new(0.0),
            load_threshold,
        }
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        let mut state = self.state.write().unwrap();
        *state = ScrubState::Paused;
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        let mut state = self.state.write().unwrap();
        if *state == ScrubState::Paused {
            *state = ScrubState::Idle;
        }
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn update_load(&self, load: f64) {
        let mut current = self.current_load.lock().unwrap();
        *current = load.clamp(0.0, 1.0);
    }

    fn get_load(&self) -> f64 {
        *self.current_load.lock().unwrap()
    }

    fn can_scrub(&self) -> bool {
        if self.is_paused() {
            return false;
        }
        self.get_load() <= self.load_threshold
    }

    fn try_start_light_scrub(&self) -> bool {
        if !self.can_scrub() {
            return false;
        }

        let mut state = self.state.write().unwrap();
        if *state == ScrubState::Idle {
            *state = ScrubState::LightScrubbing;
            true
        } else {
            false
        }
    }

    fn try_start_deep_scrub(&self) -> bool {
        if !self.can_scrub() {
            return false;
        }

        let mut state = self.state.write().unwrap();
        if *state == ScrubState::Idle {
            *state = ScrubState::DeepScrubbing;
            true
        } else {
            false
        }
    }

    fn complete_scrub(&self) {
        let mut state = self.state.write().unwrap();
        match *state {
            ScrubState::LightScrubbing => {
                self.light_scrub_count.fetch_add(1, Ordering::SeqCst);
                *state = ScrubState::Idle;
            }
            ScrubState::DeepScrubbing => {
                self.deep_scrub_count.fetch_add(1, Ordering::SeqCst);
                *state = ScrubState::Idle;
            }
            _ => {}
        }
    }

    fn get_state(&self) -> ScrubState {
        *self.state.read().unwrap()
    }

    fn light_scrub_count(&self) -> u64 {
        self.light_scrub_count.load(Ordering::SeqCst)
    }

    fn deep_scrub_count(&self) -> u64 {
        self.deep_scrub_count.load(Ordering::SeqCst)
    }
}

#[test]
fn test_scheduler_state_transitions() {
    shuttle::check_random(
        || {
            let scheduler = Arc::new(ShuttleScrubScheduler::new(0.8));

            let s1 = scheduler.clone();
            let t1 = thread::spawn(move || {
                if s1.try_start_light_scrub() {
                    // Simulate some work
                    shuttle::thread::yield_now();
                    s1.complete_scrub();
                }
            });

            let s2 = scheduler.clone();
            let t2 = thread::spawn(move || {
                if s2.try_start_deep_scrub() {
                    shuttle::thread::yield_now();
                    s2.complete_scrub();
                }
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Final state should be idle
            assert_eq!(scheduler.get_state(), ScrubState::Idle);

            // At most one of each type should have run
            // (since they can't run concurrently in our simplified model)
            let light = scheduler.light_scrub_count();
            let deep = scheduler.deep_scrub_count();
            assert!(light <= 1);
            assert!(deep <= 1);
            // At least one should have run
            assert!(light + deep >= 1);
        },
        1000,
    );
}

#[test]
fn test_pause_resume_races() {
    shuttle::check_random(
        || {
            let scheduler = Arc::new(ShuttleScrubScheduler::new(0.8));

            let s1 = scheduler.clone();
            let t1 = thread::spawn(move || {
                s1.pause();
            });

            let s2 = scheduler.clone();
            let t2 = thread::spawn(move || {
                s2.resume();
            });

            let s3 = scheduler.clone();
            let t3 = thread::spawn(move || {
                let _ = s3.try_start_light_scrub();
            });

            t1.join().unwrap();
            t2.join().unwrap();
            t3.join().unwrap();

            // State should be consistent (either Idle or Paused, not stuck)
            let state = scheduler.get_state();
            assert!(
                state == ScrubState::Idle
                    || state == ScrubState::Paused
                    || state == ScrubState::LightScrubbing
            );
        },
        1000,
    );
}

#[test]
fn test_load_update_races() {
    shuttle::check_random(
        || {
            let scheduler = Arc::new(ShuttleScrubScheduler::new(0.5));

            let s1 = scheduler.clone();
            let t1 = thread::spawn(move || {
                s1.update_load(0.3);
            });

            let s2 = scheduler.clone();
            let t2 = thread::spawn(move || {
                s2.update_load(0.9);
            });

            let s3 = scheduler.clone();
            let t3 = thread::spawn(move || {
                // This should respect load threshold
                let _ = s3.try_start_light_scrub();
            });

            t1.join().unwrap();
            t2.join().unwrap();
            t3.join().unwrap();

            // Load should be valid (clamped to 0-1)
            let load = scheduler.get_load();
            assert!(load >= 0.0 && load <= 1.0);
        },
        1000,
    );
}

#[test]
fn test_concurrent_scrub_attempts() {
    shuttle::check_random(
        || {
            let scheduler = Arc::new(ShuttleScrubScheduler::new(1.0)); // High threshold

            let handles: Vec<_> = (0..4)
                .map(|i| {
                    let s = scheduler.clone();
                    thread::spawn(move || {
                        if i % 2 == 0 {
                            s.try_start_light_scrub()
                        } else {
                            s.try_start_deep_scrub()
                        }
                    })
                })
                .collect();

            let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

            // At most one should have succeeded (mutual exclusion)
            let successful = results.iter().filter(|&&r| r).count();
            assert!(successful <= 1);
        },
        1000,
    );
}

#[test]
fn test_scrub_completion_invariants() {
    shuttle::check_random(
        || {
            let scheduler = Arc::new(ShuttleScrubScheduler::new(1.0));

            let s1 = scheduler.clone();
            let t1 = thread::spawn(move || {
                if s1.try_start_light_scrub() {
                    shuttle::thread::yield_now();
                    s1.complete_scrub();
                }
            });

            let s2 = scheduler.clone();
            let t2 = thread::spawn(move || {
                if s2.try_start_deep_scrub() {
                    shuttle::thread::yield_now();
                    s2.complete_scrub();
                }
            });

            t1.join().unwrap();
            t2.join().unwrap();

            // Completed scrubs should match state transitions
            // If a scrub completed, it should have transitioned back to Idle
            let state = scheduler.get_state();
            if scheduler.light_scrub_count() > 0 || scheduler.deep_scrub_count() > 0 {
                assert_eq!(state, ScrubState::Idle);
            }
        },
        1000,
    );
}
