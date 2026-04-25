// Copyright 2024 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cache statistics tracking and reporting module.
//!
//! Provides thread-safe counters for cache hit/miss rates, eviction counts,
//! cache size monitoring, and time-window aggregation with both JSON and
//! human-readable output formats.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use std::fmt;

/// Atomic counter that can be safely shared across threads.
#[derive(Debug)]
pub struct AtomicCounter {
    value: AtomicU64,
}

impl AtomicCounter {
    pub const fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn increment(&self) -> u64 {
        self.value.fetch_add(1, Ordering::Relaxed)
    }

    pub fn add(&self, val: u64) -> u64 {
        self.value.fetch_add(val, Ordering::Relaxed)
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::Relaxed)
    }
}

/// Time window for aggregating statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeWindow {
    LastMinute,
    LastHour,
    LastDay,
    AllTime,
}

impl fmt::Display for TimeWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeWindow::LastMinute => write!(f, "last_minute"),
            TimeWindow::LastHour => write!(f, "last_hour"),
            TimeWindow::LastDay => write!(f, "last_day"),
            TimeWindow::AllTime => write!(f, "all_time"),
        }
    }
}

impl TimeWindow {
    pub fn duration(&self) -> Option<Duration> {
        match self {
            TimeWindow::LastMinute => Some(Duration::from_secs(60)),
            TimeWindow::LastHour => Some(Duration::from_secs(3600)),
            TimeWindow::LastDay => Some(Duration::from_secs(86400)),
            TimeWindow::AllTime => None,
        }
    }
}

/// A single timestamped event for time-window tracking.
#[derive(Debug, Clone)]
struct TimestampedEvent {
    timestamp: Instant,
    is_hit: bool,
    bytes: u64,
}

/// A snapshot of cache statistics at a point in time.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub cache_size_bytes: u64,
    pub cache_entries: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub timestamp: SystemTime,
    pub uptime: Duration,
}

impl StatsSnapshot {
    /// Calculate hit rate as a percentage.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        (self.hits as f64 / total as f64) * 100.0
    }

    /// Calculate miss rate as a percentage.
    pub fn miss_rate(&self) -> f64 {
        100.0 - self.hit_rate()
    }

    /// Render stats as JSON string.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{",
                "\"hits\":{},",
                "\"misses\":{},",
                "\"hit_rate\":{:.2},",
                "\"miss_rate\":{:.2},",
                "\"evictions\":{},",
                "\"cache_size_bytes\":{},",
                "\"cache_entries\":{},",
                "\"bytes_read\":{},",
                "\"bytes_written\":{},",
                "\"uptime_secs\":{}",
                "}}"
            ),
            self.hits,
            self.misses,
            self.hit_rate(),
            self.miss_rate(),
            self.evictions,
            self.cache_size_bytes,
            self.cache_entries,
            self.bytes_read,
            self.bytes_written,
            self.uptime.as_secs(),
        )
    }
}

impl fmt::Display for StatsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Cache Statistics")?;
        writeln!(f, "================")?;
        writeln!(f, "Hits:            {}", self.hits)?;
        writeln!(f, "Misses:          {}", self.misses)?;
        writeln!(f, "Hit Rate:        {:.2}%", self.hit_rate())?;
        writeln!(f, "Evictions:       {}", self.evictions)?;
        writeln!(f, "Cache Size:      {} bytes", self.cache_size_bytes)?;
        writeln!(f, "Cache Entries:   {}", self.cache_entries)?;
        writeln!(f, "Bytes Read:      {}", self.bytes_read)?;
        writeln!(f, "Bytes Written:   {}", self.bytes_written)?;
        writeln!(f, "Uptime:          {} secs", self.uptime.as_secs())?;
        Ok(())
    }
}

/// Thread-safe cache statistics tracker.
#[derive(Debug)]
pub struct CacheStats {
    hits: AtomicCounter,
    misses: AtomicCounter,
    evictions: AtomicCounter,
    cache_size_bytes: AtomicCounter,
    cache_entries: AtomicCounter,
    bytes_read: AtomicCounter,
    bytes_written: AtomicCounter,
    start_time: Instant,
    events: Mutex<Vec<TimestampedEvent>>,
}

impl CacheStats {
    /// Create a new statistics tracker.
    pub fn new() -> Self {
        Self {
            hits: AtomicCounter::new(),
            misses: AtomicCounter::new(),
            evictions: AtomicCounter::new(),
            cache_size_bytes: AtomicCounter::new(),
            cache_entries: AtomicCounter::new(),
            bytes_read: AtomicCounter::new(),
            bytes_written: AtomicCounter::new(),
            start_time: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    /// Record a cache hit.
    pub fn record_hit(&self, bytes: u64) {
        self.hits.increment();
        self.bytes_read.add(bytes);
        if let Ok(mut events) = self.events.lock() {
            events.push(TimestampedEvent {
                timestamp: Instant::now(),
                is_hit: true,
                bytes,
            });
        }
    }

    /// Record a cache miss.
    pub fn record_miss(&self) {
        self.misses.increment();
        if let Ok(mut events) = self.events.lock() {
            events.push(TimestampedEvent {
                timestamp: Instant::now(),
                is_hit: false,
                bytes: 0,
            });
        }
    }

    /// Record a cache eviction.
    pub fn record_eviction(&self) {
        self.evictions.increment();
    }

    /// Record bytes written to cache.
    pub fn record_write(&self, bytes: u64) {
        self.bytes_written.add(bytes);
    }

    /// Update the current cache size and entry count.
    pub fn update_size(&self, size_bytes: u64, entries: u64) {
        self.cache_size_bytes.value.store(size_bytes, Ordering::Relaxed);
        self.cache_entries.value.store(entries, Ordering::Relaxed);
    }

    /// Take a snapshot of all-time statistics.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            hits: self.hits.get(),
            misses: self.misses.get(),
            evictions: self.evictions.get(),
            cache_size_bytes: self.cache_size_bytes.get(),
            cache_entries: self.cache_entries.get(),
            bytes_read: self.bytes_read.get(),
            bytes_written: self.bytes_written.get(),
            timestamp: SystemTime::now(),
            uptime: self.start_time.elapsed(),
        }
    }

    /// Get statistics for a specific time window.
    pub fn snapshot_for_window(&self, window: TimeWindow) -> StatsSnapshot {
        if window == TimeWindow::AllTime {
            return self.snapshot();
        }

        let duration = window.duration().unwrap();
        let cutoff = Instant::now() - duration;
        let mut hits = 0u64;
        let mut misses = 0u64;
        let mut bytes_read = 0u64;

        if let Ok(events) = self.events.lock() {
            for event in events.iter() {
                if event.timestamp >= cutoff {
                    if event.is_hit {
                        hits += 1;
                        bytes_read += event.bytes;
                    } else {
                        misses += 1;
                    }
                }
            }
        }

        StatsSnapshot {
            hits,
            misses,
            evictions: self.evictions.get(),
            cache_size_bytes: self.cache_size_bytes.get(),
            cache_entries: self.cache_entries.get(),
            bytes_read,
            bytes_written: self.bytes_written.get(),
            timestamp: SystemTime::now(),
            uptime: self.start_time.elapsed(),
        }
    }

    /// Prune old events outside the largest window (1 day).
    pub fn prune_old_events(&self) {
        let cutoff = Instant::now() - Duration::from_secs(86400);
        if let Ok(mut events) = self.events.lock() {
            events.retain(|e| e.timestamp >= cutoff);
        }
    }

    /// Reset all statistics counters and clear event history.
    pub fn reset(&self) {
        self.hits.reset();
        self.misses.reset();
        self.evictions.reset();
        self.bytes_read.reset();
        self.bytes_written.reset();
        if let Ok(mut events) = self.events.lock() {
            events.clear();
        }
    }
}

/// Thread-safe shared statistics handle.
pub type SharedCacheStats = Arc<CacheStats>;

/// Create a new shared statistics instance.
pub fn new_shared_stats() -> SharedCacheStats {
    Arc::new(CacheStats::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_atomic_counter_basic() {
        let counter = AtomicCounter::new();
        assert_eq!(counter.get(), 0);
        counter.increment();
        assert_eq!(counter.get(), 1);
        counter.add(5);
        assert_eq!(counter.get(), 6);
        let old = counter.reset();
        assert_eq!(old, 6);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_atomic_counter_thread_safety() {
        let counter = Arc::new(AtomicCounter::new());
        let mut handles = vec![];
        for _ in 0..10 {
            let c = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.increment();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(counter.get(), 10_000);
    }

    #[test]
    fn test_hit_rate_calculation() {
        let stats = CacheStats::new();
        // No events: 0% hit rate
        let snap = stats.snapshot();
        assert_eq!(snap.hit_rate(), 0.0);
        assert_eq!(snap.miss_rate(), 0.0);

        // Record some hits and misses
        stats.record_hit(100);
        stats.record_hit(200);
        stats.record_miss();
        stats.record_miss();
        let snap = stats.snapshot();
        assert_eq!(snap.hits, 2);
        assert_eq!(snap.misses, 2);
        assert!((snap.hit_rate() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_eviction_tracking() {
        let stats = CacheStats::new();
        stats.record_eviction();
        stats.record_eviction();
        stats.record_eviction();
        assert_eq!(stats.snapshot().evictions, 3);
    }

    #[test]
    fn test_cache_size_update() {
        let stats = CacheStats::new();
        stats.update_size(1024 * 1024, 42);
        let snap = stats.snapshot();
        assert_eq!(snap.cache_size_bytes, 1024 * 1024);
        assert_eq!(snap.cache_entries, 42);
    }

    #[test]
    fn test_bytes_tracking() {
        let stats = CacheStats::new();
        stats.record_hit(500);
        stats.record_hit(300);
        stats.record_write(1000);
        stats.record_write(2000);
        let snap = stats.snapshot();
        assert_eq!(snap.bytes_read, 800);
        assert_eq!(snap.bytes_written, 3000);
    }

    #[test]
    fn test_time_window_filtering() {
        let stats = CacheStats::new();
        stats.record_hit(100);
        stats.record_miss();
        let snap = stats.snapshot_for_window(TimeWindow::LastMinute);
        assert_eq!(snap.hits, 1);
        assert_eq!(snap.misses, 1);
        let snap_all = stats.snapshot_for_window(TimeWindow::AllTime);
        assert_eq!(snap_all.hits, 1);
    }

    #[test]
    fn test_reset_clears_counters() {
        let stats = CacheStats::new();
        stats.record_hit(100);
        stats.record_miss();
        stats.record_eviction();
        stats.record_write(500);
        stats.reset();
        let snap = stats.snapshot();
        assert_eq!(snap.hits, 0);
        assert_eq!(snap.misses, 0);
        assert_eq!(snap.evictions, 0);
        assert_eq!(snap.bytes_read, 0);
        assert_eq!(snap.bytes_written, 0);
    }

    #[test]
    fn test_json_output() {
        let stats = CacheStats::new();
        stats.record_hit(100);
        stats.record_miss();
        stats.update_size(2048, 5);
        let snap = stats.snapshot();
        let json = snap.to_json();
        assert!(json.contains("\"hits\":1"));
        assert!(json.contains("\"misses\":1"));
        assert!(json.contains("\"cache_size_bytes\":2048"));
        assert!(json.contains("\"cache_entries\":5"));
        assert!(json.contains("\"hit_rate\":50.00"));
    }

    #[test]
    fn test_human_readable_output() {
        let stats = CacheStats::new();
        stats.record_hit(100);
        stats.record_miss();
        let snap = stats.snapshot();
        let output = format!("{}", snap);
        assert!(output.contains("Cache Statistics"));
        assert!(output.contains("Hits:"));
        assert!(output.contains("Misses:"));
        assert!(output.contains("Hit Rate:"));
    }

    #[test]
    fn test_shared_stats() {
        let stats = new_shared_stats();
        let s1 = Arc::clone(&stats);
        let s2 = Arc::clone(&stats);
        let h1 = thread::spawn(move || {
            for _ in 0..100 {
                s1.record_hit(10);
            }
        });
        let h2 = thread::spawn(move || {
            for _ in 0..100 {
                s2.record_miss();
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();
        let snap = stats.snapshot();
        assert_eq!(snap.hits, 100);
        assert_eq!(snap.misses, 100);
    }

    #[test]
    fn test_prune_old_events() {
        let stats = CacheStats::new();
        stats.record_hit(100);
        stats.record_miss();
        // Pruning shouldn't remove recent events
        stats.prune_old_events();
        let snap = stats.snapshot_for_window(TimeWindow::LastMinute);
        assert_eq!(snap.hits, 1);
        assert_eq!(snap.misses, 1);
    }

    #[test]
    fn test_time_window_display() {
        assert_eq!(format!("{}", TimeWindow::LastMinute), "last_minute");
        assert_eq!(format!("{}", TimeWindow::LastHour), "last_hour");
        assert_eq!(format!("{}", TimeWindow::LastDay), "last_day");
        assert_eq!(format!("{}", TimeWindow::AllTime), "all_time");
    }

    #[test]
    fn test_time_window_duration() {
        assert_eq!(TimeWindow::LastMinute.duration(), Some(Duration::from_secs(60)));
        assert_eq!(TimeWindow::LastHour.duration(), Some(Duration::from_secs(3600)));
        assert_eq!(TimeWindow::LastDay.duration(), Some(Duration::from_secs(86400)));
        assert_eq!(TimeWindow::AllTime.duration(), None);
    }
}
