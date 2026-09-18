//! The container's own resource usage, read from its cgroup v2 files and
//! published as Prometheus metrics.
//!
//! Each instance reports its memory against its limit, its CPU throttling and
//! its start time, so the container alerts need no exporter on the host and
//! work whatever the container runtime.

use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// How often the metrics are refreshed.
const INTERVAL: Duration = Duration::from_secs(10);

/// The cgroup the process runs in, as a container with a private cgroup
/// namespace sees it.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Publish the start time and the cgroup metrics every [`INTERVAL`] for the
/// life of the process. Outside a cgroup v2 (a developer machine), only the
/// start time is published.
///
/// Every tick sets the start time again: the metrics recorder may be installed
/// after this is called, and a value set before it would be lost.
pub fn spawn() {
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let root = PathBuf::from(CGROUP_ROOT);
    let in_cgroup = root.join("cpu.stat").is_file();
    if !in_cgroup {
        tracing::info!("no cgroup v2 found: container metrics disabled");
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            metrics::gauge!("auth_process_start_time_seconds").set(started);
            if in_cgroup {
                record(&root);
            }
        }
    });
}

fn record(root: &Path) {
    let read = |file: &str| std::fs::read_to_string(root.join(file)).ok();

    if let Some(current) = read("memory.current").and_then(|c| parse_u64(&c)) {
        let inactive_file = read("memory.stat")
            .and_then(|s| stat_field(&s, "inactive_file"))
            .unwrap_or(0);
        metrics::gauge!("auth_container_memory_working_set_bytes")
            .set(working_set(current, inactive_file) as f64);
    }
    // `max` (no limit) publishes 0, which the alert ignores.
    if let Some(max) = read("memory.max") {
        metrics::gauge!("auth_container_memory_limit_bytes")
            .set(parse_u64(&max).unwrap_or(0) as f64);
    }
    if let Some(stat) = read("cpu.stat") {
        if let Some(periods) = stat_field(&stat, "nr_periods") {
            metrics::counter!("auth_container_cpu_periods_total").absolute(periods);
        }
        if let Some(throttled) = stat_field(&stat, "nr_throttled") {
            metrics::counter!("auth_container_cpu_throttled_periods_total").absolute(throttled);
        }
    }
}

/// Memory the kernel cannot reclaim without swapping: the usage minus the page
/// cache it can drop, as the out-of-memory killer and cAdvisor count it.
fn working_set(current: u64, inactive_file: u64) -> u64 {
    current.saturating_sub(inactive_file)
}

fn parse_u64(contents: &str) -> Option<u64> {
    contents.trim().parse().ok()
}

/// The value of `key` in a flat-keyed cgroup file (`memory.stat`, `cpu.stat`).
fn stat_field(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let (name, value) = line.split_once(' ')?;
        (name == key).then(|| parse_u64(value)).flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU_STAT: &str = "usage_usec 81234\nuser_usec 60000\nsystem_usec 21234\n\
        nr_periods 1200\nnr_throttled 37\nthrottled_usec 912000\n";

    #[test]
    fn cpu_stat_fields_are_read_by_exact_name() {
        assert_eq!(stat_field(CPU_STAT, "nr_periods"), Some(1200));
        assert_eq!(stat_field(CPU_STAT, "nr_throttled"), Some(37));
        assert_eq!(stat_field(CPU_STAT, "throttled"), None);
    }

    #[test]
    fn a_missing_or_malformed_field_is_absent() {
        assert_eq!(stat_field("nr_periods\n", "nr_periods"), None);
        assert_eq!(stat_field("nr_periods many\n", "nr_periods"), None);
        assert_eq!(stat_field("", "nr_periods"), None);
    }

    #[test]
    fn an_unlimited_memory_max_has_no_value() {
        assert_eq!(parse_u64("536870912\n"), Some(536_870_912));
        assert_eq!(parse_u64("max\n"), None);
    }

    #[test]
    fn the_working_set_leaves_out_reclaimable_page_cache() {
        let stat = "anon 1000\nfile 5000\nactive_file 2000\ninactive_file 3000\n";
        let inactive = stat_field(stat, "inactive_file").unwrap();
        assert_eq!(working_set(10_000, inactive), 7_000);
        assert_eq!(working_set(1_000, 3_000), 0);
    }

    #[test]
    fn metrics_are_read_from_a_cgroup_directory() {
        let dir = std::env::temp_dir().join(format!("auth-api-cgroup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("memory.current"), "4096\n").unwrap();
        std::fs::write(dir.join("memory.stat"), "inactive_file 1024\n").unwrap();
        std::fs::write(dir.join("memory.max"), "max\n").unwrap();
        std::fs::write(dir.join("cpu.stat"), CPU_STAT).unwrap();

        // Without a recorder installed the metrics are discarded: this checks
        // the files are read without a panic, whatever they contain.
        record(&dir);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
