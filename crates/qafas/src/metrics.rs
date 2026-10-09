//! `GET /metrics`, Prometheus text format, written by hand.
//!
//! Everything countable is already an `Event`, so the collector is one
//! subscriber on the existing bus rather than a counter sprinkled through the
//! code. Gauges (sandboxes by tier, warm pool) are read at scrape time from the
//! same state `/sandboxes` and `/pool` serve, so they cannot drift from it.
//!
//! design: fixed-bucket histogram and atomics, no client library. A Prometheus
//! text page is 40 lines of formatting; `prometheus` would be a dependency, a
//! registry and a macro layer for the same output.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use proto::EventType;

use crate::events::Bus;

/// Upper bounds in milliseconds. The first three are where the tiers separate:
/// a native exec should land in 1–10 ms, a VM exec in 2–25 ms. v5 adds the tail
/// (5 s, 30 s, 5 min): a build or an `npm ci` used to land in `+Inf` with
/// everything else, which made the p99 unreadable.
const BUCKETS: [u64; 12] = [1, 2, 5, 10, 25, 50, 100, 500, 1000, 5000, 30000, 300_000];

/// One fixed-bucket histogram. Two of them now (exec round trip, create), which
/// is why the counting and the four exposition lines live in one place.
#[derive(Default)]
struct Hist {
    buckets: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    sum_ms: AtomicU64,
}

impl Hist {
    fn observe(&self, ms: u64) {
        self.count.fetch_add(1, Relaxed);
        self.sum_ms.fetch_add(ms, Relaxed);
        for (i, b) in BUCKETS.iter().enumerate() {
            if ms <= *b {
                self.buckets[i].fetch_add(1, Relaxed);
            }
        }
    }

    fn render(&self, s: &mut String, name: &str, help: &str) {
        let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} histogram");
        for (i, b) in BUCKETS.iter().enumerate() {
            let _ = writeln!(s, "{name}_bucket{{le=\"{b}\"}} {}", self.buckets[i].load(Relaxed));
        }
        let count = self.count.load(Relaxed);
        let _ = writeln!(s, "{name}_bucket{{le=\"+Inf\"}} {count}");
        let _ = writeln!(s, "{name}_sum {}", self.sum_ms.load(Relaxed));
        let _ = writeln!(s, "{name}_count {count}");
    }
}

/// `Instant` has no `Default`, and the daemon's uptime starts when its metrics do.
struct Started(std::time::Instant);
impl Default for Started {
    fn default() -> Self {
        Self(std::time::Instant::now())
    }
}

#[derive(Default)]
pub struct Metrics {
    events: Mutex<BTreeMap<&'static str, u64>>,
    alerts: Mutex<BTreeMap<(String, String), u64>>,
    exec: Hist,
    /// v4. Boot time as reported by `sandbox.ready`.
    create: Hist,
    egress_bytes: Mutex<BTreeMap<&'static str, u64>>,
    tier_selected: Mutex<BTreeMap<String, u64>>,
    /// v4. Acquires served from the warm pool, and paid for cold.
    pool_hit: [AtomicU64; 2],
    /// Event batches the control plane would not take, and what became of them:
    /// `[spooled, replayed, dropped]`. A spool that only grows is the signal an
    /// operator needs before the cap starts losing events.
    spool: [AtomicU64; 3],
    started: Started,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// One task, counting every event that crosses the bus.
    pub fn spawn(self: &Arc<Self>, bus: Bus) {
        let m = self.clone();
        // Subscribed before the task starts, so nothing emitted during startup
        // is missed.
        let mut rx = bus.subscribe();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(e) => m.observe(&e),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Losing counts is better than blocking the bus; say so.
                        tracing::warn!(dropped = n, "metrics collector lagged");
                    }
                    Err(_) => return,
                }
            }
        });
    }

    /// v4. Whether an acquire came out of the warm pool. Not an event: the pool
    /// reports `warm` to its caller, and nothing else needs to know.
    pub fn pool_result(&self, warm: bool) {
        self.pool_hit[usize::from(warm)].fetch_add(1, Relaxed);
    }

    /// `n` batches written to the spool, `dropped` older ones evicted by its cap.
    pub fn spooled(&self, n: u64, dropped: u64) {
        self.spool[0].fetch_add(n, Relaxed);
        self.spool[2].fetch_add(dropped, Relaxed);
    }

    /// `n` spooled batches finally delivered.
    pub fn replayed(&self, n: u64) {
        self.spool[1].fetch_add(n, Relaxed);
    }

    pub fn observe(&self, e: &proto::Event) {
        *self.events.lock().unwrap().entry(e.r#type.as_str()).or_default() += 1;
        match e.r#type {
            EventType::ExecEnd => {
                if let Some(ms) = e.data.get("duration_ms").and_then(|v| v.as_u64()) {
                    self.exec.observe(ms);
                }
            }
            EventType::SandboxReady => {
                if let Some(ms) = e.data.get("boot_ms").and_then(|v| v.as_u64()) {
                    self.create.observe(ms);
                }
            }
            EventType::SecurityAlert => {
                let key = (
                    e.data["rule"].as_str().unwrap_or("unknown").to_string(),
                    e.data["severity"].as_str().unwrap_or("unknown").to_string(),
                );
                *self.alerts.lock().unwrap().entry(key).or_default() += 1;
            }
            EventType::EgressAllow | EventType::EgressDeny => {
                let k = if e.r#type == EventType::EgressAllow { "allow" } else { "deny" };
                let n = e.data.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                *self.egress_bytes.lock().unwrap().entry(k).or_default() += n;
            }
            EventType::SandboxTierSelected => {
                let t = e.data["selected"].as_str().unwrap_or("unknown").to_string();
                *self.tier_selected.lock().unwrap().entry(t).or_default() += 1;
            }
            _ => {}
        }
    }

    /// Prometheus text exposition. `gauges` is whatever the caller can only know
    /// at scrape time.
    pub fn render(&self, gauges: &Gauges) -> String {
        let mut s = String::with_capacity(2048);

        s.push_str("# HELP sbx_sandboxes Live sandboxes by tier and state.\n# TYPE sbx_sandboxes gauge\n");
        for ((tier, state), n) in &gauges.sandboxes {
            let _ = writeln!(s, "sbx_sandboxes{{tier=\"{}\",state=\"{}\"}} {n}", esc(tier), esc(state));
        }
        s.push_str("# HELP sbx_sandbox_age_seconds_max Oldest live sandbox, by tier.\n# TYPE sbx_sandbox_age_seconds_max gauge\n");
        for (tier, n) in &gauges.age_max {
            let _ = writeln!(s, "sbx_sandbox_age_seconds_max{{tier=\"{}\"}} {n}", esc(tier));
        }
        s.push_str("# HELP sbx_sandbox_idle_seconds_max Longest idle live sandbox, by tier.\n# TYPE sbx_sandbox_idle_seconds_max gauge\n");
        for (tier, n) in &gauges.idle_max {
            let _ = writeln!(s, "sbx_sandbox_idle_seconds_max{{tier=\"{}\"}} {n}", esc(tier));
        }
        s.push_str("# HELP sbx_pool_warm Warm sandboxes waiting in the pool.\n# TYPE sbx_pool_warm gauge\n");
        for (key, n) in &gauges.pool {
            let _ = writeln!(s, "sbx_pool_warm{{key=\"{}\"}} {n}", esc(key));
        }
        s.push_str("# HELP sbx_tiers_available Tiers this host can serve.\n# TYPE sbx_tiers_available gauge\n");
        for t in &gauges.tiers {
            let _ = writeln!(s, "sbx_tiers_available{{tier=\"{}\"}} 1", esc(t));
        }

        // v5 §3a. Per sandbox: what it is allowed and what it is using. The
        // limit gauges are emitted even before the first usage sample, so
        // "committed vs used" has both halves from the first scrape.
        if !gauges.per_sandbox.is_empty() {
            for (name, help, kind) in PER_SANDBOX_HELP {
                let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} {kind}");
            }
            for g in &gauges.per_sandbox {
                let l = format!(
                    "id=\"{}\",tier=\"{}\",size=\"{}\",pi_session=\"{}\"",
                    esc(&g.id),
                    esc(&g.tier),
                    esc(&g.size),
                    esc(&g.pi_session)
                );
                let _ = writeln!(s, "sbx_sandbox_limit_memory_bytes{{{l}}} {}", g.limits.mem_mib * 1024 * 1024);
                let _ = writeln!(s, "sbx_sandbox_limit_cpus{{{l}}} {}", g.limits.cpus);
                let _ = writeln!(s, "sbx_sandbox_limit_disk_bytes{{{l}}} {}", g.limits.disk_mib * 1024 * 1024);
                let Some(u) = &g.usage else { continue };
                let _ = writeln!(s, "sbx_sandbox_memory_bytes{{{l}}} {}", u.mem_bytes);
                let _ = writeln!(s, "sbx_sandbox_memory_peak_bytes{{{l}}} {}", u.mem_peak_bytes);
                let _ = writeln!(s, "sbx_sandbox_cpu_seconds_total{{{l}}} {:.3}", u.cpu_millis as f64 / 1000.0);
                let _ = writeln!(s, "sbx_sandbox_pids{{{l}}} {}", u.pids);
                let _ = writeln!(s, "sbx_sandbox_disk_bytes{{{l}}} {}", u.disk_bytes);
            }
        }

        s.push_str("# HELP sbx_event_batches_total Event batches to the control plane, by outcome.\n# TYPE sbx_event_batches_total counter\n");
        for (i, outcome) in ["spooled", "replayed", "dropped"].iter().enumerate() {
            let _ = writeln!(s, "sbx_event_batches_total{{outcome=\"{outcome}\"}} {}", self.spool[i].load(Relaxed));
        }

        s.push_str("# HELP sbx_events_total Events emitted, by type.\n# TYPE sbx_events_total counter\n");
        for (ty, n) in self.events.lock().unwrap().iter() {
            let _ = writeln!(s, "sbx_events_total{{type=\"{ty}\"}} {n}");
        }

        s.push_str("# HELP sbx_alerts_total Security alerts, by rule and severity.\n# TYPE sbx_alerts_total counter\n");
        for ((rule, sev), n) in self.alerts.lock().unwrap().iter() {
            let _ = writeln!(s, "sbx_alerts_total{{rule=\"{}\",severity=\"{}\"}} {n}", esc(rule), esc(sev));
        }

        self.exec.render(&mut s, "sbx_exec_duration_ms", "Exec round trip, as measured by the proxy layer.");
        self.create.render(&mut s, "sbx_create_duration_ms", "Sandbox boot time, as reported by sandbox.ready.");

        s.push_str("# HELP sbx_pool_hit_total Acquires served warm from the pool, and paid for cold.\n# TYPE sbx_pool_hit_total counter\n");
        for (i, hit) in ["false", "true"].iter().enumerate() {
            let _ = writeln!(s, "sbx_pool_hit_total{{hit=\"{hit}\"}} {}", self.pool_hit[i].load(Relaxed));
        }

        s.push_str("# HELP sbx_egress_bytes_total Bytes through the egress proxy, by decision.\n# TYPE sbx_egress_bytes_total counter\n");
        for (k, n) in self.egress_bytes.lock().unwrap().iter() {
            let _ = writeln!(s, "sbx_egress_bytes_total{{decision=\"{k}\"}} {n}");
        }

        s.push_str("# HELP sbx_tier_selected_total Tier decisions taken.\n# TYPE sbx_tier_selected_total counter\n");
        for (t, n) in self.tier_selected.lock().unwrap().iter() {
            let _ = writeln!(s, "sbx_tier_selected_total{{tier=\"{}\"}} {n}", esc(t));
        }

        s.push_str("# HELP sbx_build_info Daemon version, as a label.\n# TYPE sbx_build_info gauge\n");
        let _ = writeln!(s, "sbx_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"));
        s.push_str("# HELP sbx_uptime_seconds Seconds since this daemon started.\n# TYPE sbx_uptime_seconds gauge\n");
        let _ = writeln!(s, "sbx_uptime_seconds {}", self.started.0.elapsed().as_secs());
        s
    }
}

/// v5 §3a. `HELP`/`TYPE` for the per-sandbox series, once per page rather than
/// once per sandbox (Prometheus rejects a repeated `HELP`).
const PER_SANDBOX_HELP: [(&str, &str, &str); 8] = [
    ("sbx_sandbox_limit_memory_bytes", "Memory ceiling of one sandbox.", "gauge"),
    ("sbx_sandbox_limit_cpus", "CPU ceiling of one sandbox.", "gauge"),
    ("sbx_sandbox_limit_disk_bytes", "Scratch ceiling of one sandbox.", "gauge"),
    ("sbx_sandbox_memory_bytes", "Memory in use by one sandbox.", "gauge"),
    ("sbx_sandbox_memory_peak_bytes", "High-water memory of one sandbox.", "gauge"),
    ("sbx_sandbox_cpu_seconds_total", "CPU seconds used by one sandbox.", "counter"),
    ("sbx_sandbox_pids", "Processes in one sandbox.", "gauge"),
    ("sbx_sandbox_disk_bytes", "Scratch in use by one sandbox.", "gauge"),
];

/// Label values come from workspace paths and rule names; a stray quote or
/// newline would produce a page Prometheus rejects.
fn esc(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ")
}

#[derive(Default)]
pub struct Gauges {
    /// v4: keyed by `(tier, state)`.
    pub sandboxes: BTreeMap<(String, String), u64>,
    /// v4: oldest and longest-idle live sandbox per tier, seconds.
    pub age_max: BTreeMap<String, u64>,
    pub idle_max: BTreeMap<String, u64>,
    pub pool: BTreeMap<String, u64>,
    pub tiers: Vec<String>,
    /// v5 §3a: one row per live sandbox, limits and latest usage sample.
    pub per_sandbox: Vec<SandboxGauge>,
}

/// v5 §3a. What `/metrics` says about one live sandbox. `usage` is the last
/// boundary sample (absent until the first one), `limits` is always known.
pub struct SandboxGauge {
    pub id: String,
    pub tier: String,
    pub size: String,
    pub pi_session: String,
    pub limits: proto::SandboxLimits,
    pub usage: Option<proto::SandboxUsage>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(ty: EventType, data: serde_json::Value) -> proto::Event {
        proto::Event {
            id: "1".into(),
            ts: "t".into(),
            host_id: "h".into(),
            sandbox_id: "s".into(),
            pi_session: String::new(),
            tool_call_id: String::new(),
            r#type: ty,
            data,
        }
    }

    #[test]
    fn counters_and_histogram_render() {
        let m = Metrics::new();
        m.observe(&ev(EventType::ExecEnd, json!({"duration_ms": 3})));
        m.observe(&ev(EventType::ExecEnd, json!({"duration_ms": 300})));
        m.observe(&ev(EventType::SecurityAlert, json!({"rule": "canary.read", "severity": "critical"})));
        m.observe(&ev(EventType::EgressAllow, json!({"bytes": 100})));
        m.observe(&ev(EventType::EgressDeny, json!({"bytes": 0})));
        m.observe(&ev(EventType::SandboxTierSelected, json!({"selected": "native"})));
        // v4
        m.observe(&ev(EventType::SandboxReady, json!({"boot_ms": 40})));
        m.pool_result(true);
        m.pool_result(true);
        m.pool_result(false);

        let g = Gauges {
            sandboxes: BTreeMap::from([(("native".into(), "ready".into()), 2), (("vm".into(), "stopped".into()), 1)]),
            age_max: BTreeMap::from([("native".into(), 900)]),
            idle_max: BTreeMap::from([("native".into(), 12)]),
            pool: BTreeMap::from([("base|/w".into(), 1)]),
            tiers: vec!["native".into(), "vm".into()],
            // v5 §3a: one sized sandbox with a sample, one without.
            per_sandbox: vec![
                SandboxGauge {
                    id: "sbx_a".into(),
                    tier: "vm".into(),
                    size: "mini".into(),
                    pi_session: "s1".into(),
                    limits: proto::sizes::default_table()["mini"],
                    usage: Some(proto::SandboxUsage {
                        cpu_millis: 1900,
                        mem_bytes: 569_376_768,
                        mem_peak_bytes: 700_000_000,
                        disk_bytes: 1024,
                        pids: 13,
                        ts: "t".into(),
                    }),
                },
                SandboxGauge {
                    id: "sbx_b".into(),
                    tier: "native".into(),
                    size: "custom".into(),
                    pi_session: String::new(),
                    limits: proto::SandboxLimits { cpus: 0.5, mem_mib: 512, disk_mib: 512, pids: 128 },
                    usage: None,
                },
            ],
        };
        let out = m.render(&g);
        for want in [
            "sbx_sandboxes{tier=\"native\",state=\"ready\"} 2",
            "sbx_sandboxes{tier=\"vm\",state=\"stopped\"} 1",
            "sbx_sandbox_age_seconds_max{tier=\"native\"} 900",
            "sbx_sandbox_idle_seconds_max{tier=\"native\"} 12",
            // 40 ms boot: past the 25 ms bucket, inside the 50 ms one.
            "sbx_create_duration_ms_bucket{le=\"25\"} 0",
            "sbx_create_duration_ms_bucket{le=\"50\"} 1",
            "sbx_create_duration_ms_count 1",
            "sbx_create_duration_ms_sum 40",
            "sbx_pool_hit_total{hit=\"true\"} 2",
            "sbx_pool_hit_total{hit=\"false\"} 1",
            "sbx_uptime_seconds 0",
            concat!("sbx_build_info{version=\"", env!("CARGO_PKG_VERSION"), "\"} 1"),
            "sbx_pool_warm{key=\"base|/w\"} 1",
            "sbx_tiers_available{tier=\"vm\"} 1",
            "sbx_events_total{type=\"exec.end\"} 2",
            "sbx_alerts_total{rule=\"canary.read\",severity=\"critical\"} 1",
            // 3 ms lands in the 5 ms bucket but not the 2 ms one.
            "sbx_exec_duration_ms_bucket{le=\"2\"} 0",
            "sbx_exec_duration_ms_bucket{le=\"5\"} 1",
            "sbx_exec_duration_ms_bucket{le=\"500\"} 2",
            "sbx_exec_duration_ms_bucket{le=\"+Inf\"} 2",
            "sbx_exec_duration_ms_sum 303",
            "sbx_exec_duration_ms_count 2",
            "sbx_egress_bytes_total{decision=\"allow\"} 100",
            "sbx_tier_selected_total{tier=\"native\"} 1",
            // v5: the tail buckets, so a 5-minute build is not just `+Inf`.
            "sbx_exec_duration_ms_bucket{le=\"5000\"} 2",
            "sbx_exec_duration_ms_bucket{le=\"300000\"} 2",
            // v5 per-sandbox gauges, all four labels, limits and usage.
            "sbx_sandbox_limit_memory_bytes{id=\"sbx_a\",tier=\"vm\",size=\"mini\",pi_session=\"s1\"} 1073741824",
            "sbx_sandbox_limit_cpus{id=\"sbx_a\",tier=\"vm\",size=\"mini\",pi_session=\"s1\"} 1",
            "sbx_sandbox_limit_disk_bytes{id=\"sbx_a\",tier=\"vm\",size=\"mini\",pi_session=\"s1\"} 1073741824",
            "sbx_sandbox_memory_bytes{id=\"sbx_a\",tier=\"vm\",size=\"mini\",pi_session=\"s1\"} 569376768",
            "sbx_sandbox_memory_peak_bytes{id=\"sbx_a\",tier=\"vm\",size=\"mini\",pi_session=\"s1\"} 700000000",
            "sbx_sandbox_cpu_seconds_total{id=\"sbx_a\",tier=\"vm\",size=\"mini\",pi_session=\"s1\"} 1.900",
            "sbx_sandbox_pids{id=\"sbx_a\",tier=\"vm\",size=\"mini\",pi_session=\"s1\"} 13",
            "sbx_sandbox_disk_bytes{id=\"sbx_a\",tier=\"vm\",size=\"mini\",pi_session=\"s1\"} 1024",
            // A sandbox with no sample yet still publishes its ceilings.
            "sbx_sandbox_limit_cpus{id=\"sbx_b\",tier=\"native\",size=\"custom\",pi_session=\"\"} 0.5",
        ] {
            assert!(out.contains(want), "missing {want:?} in:\n{out}");
        }
        assert!(!out.contains("sbx_sandbox_pids{id=\"sbx_b\""), "no usage means no usage series");
        // One `HELP` per metric name, however many sandboxes there are.
        assert_eq!(out.matches("# HELP sbx_sandbox_memory_bytes ").count(), 1);
    }

    #[test]
    fn label_values_cannot_break_the_page() {
        let m = Metrics::new();
        m.observe(&ev(EventType::SecurityAlert, json!({"rule": "we\"ird\nrule", "severity": "low"})));
        let out = m.render(&Gauges::default());
        assert!(out.contains(r#"rule="we\"ird rule""#), "{out}");
        assert!(out.lines().all(|l| l.starts_with('#') || l.matches('{').count() <= 1));
    }

    #[test]
    fn an_alert_without_fields_does_not_panic() {
        let m = Metrics::new();
        m.observe(&ev(EventType::SecurityAlert, json!({})));
        m.observe(&ev(EventType::ExecEnd, json!({})));
        assert!(m.render(&Gauges::default()).contains("severity=\"unknown\""));
    }
}
