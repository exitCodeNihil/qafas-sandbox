//! The macOS half of "we must see when an agent tries to escape".
//!
//! Seatbelt denials are reported by the kernel to the unified log, tagged with
//! the `(with message ...)` string the profile carries. One `log stream` per
//! daemon reads them, splits the tag into `SBX/<sandbox id>/<rule>`, and turns
//! each into a `security.alert` on the right sandbox with the right rule name.
//!
//! This is the authoritative feed for the native tier (D18). It sees every
//! denied open, not just the ones that appear on a command line, because the
//! kernel is the one reporting. Its one weakness is latency — the unified log
//! delivers in roughly a second — which is acceptable because the *denial*
//! already happened synchronously and the caller saw EPERM.

use proto::{EventType, Severity};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::backend::native::Registry;
use crate::seatbelt::MARKER;

/// A parsed denial line: `Sandbox: node(1234) deny(1) file-read-data /path`.
#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    pub process: String,
    pub pid: u32,
    pub op: String,
    pub path: String,
}

/// Noise every macOS process generates and nobody wants an alert about.
const IGNORED: &[&str] = &[
    "mach-lookup com.apple.diagnosticd",
    "mach-lookup com.apple.analyticsd",
    "mach-lookup com.apple.dt.CommandLineTools.installondemand",
    "mDNSResponder",
    "file-write-data /dev/dtracehelper",
];

pub fn parse_violation(line: &str) -> Option<Violation> {
    let rest = line.split("Sandbox: ").nth(1)?;
    let (head, rest) = rest.split_once(" deny(")?;
    let rest = rest.split_once(')')?.1.trim_start();
    let (proc_name, pid) = head.rsplit_once('(')?;
    let (op, path) = match rest.split_once(' ') {
        Some((op, path)) => (op, path),
        None => (rest, ""),
    };
    Some(Violation {
        process: proc_name.trim().to_string(),
        pid: pid.trim_end_matches(')').parse().ok()?,
        op: op.to_string(),
        path: path.trim().to_string(),
    })
}

/// `SBX/<sandbox id>/<rule>` anywhere on a line.
pub fn parse_tag(line: &str) -> Option<(String, String)> {
    let at = line.find(MARKER)?;
    let mut it = line[at..].split('/');
    it.next()?;
    let id = it.next()?.trim();
    let rule = it.next()?.trim().trim_end_matches(|c: char| c.is_whitespace());
    (!id.is_empty() && !rule.is_empty()).then(|| (id.to_string(), rule.to_string()))
}

fn severity(rule: &str, op: &str) -> Severity {
    use proto::rules as r;
    match rule {
        r::CANARY_READ => Severity::Critical,
        r::ESCAPE_PROBE => Severity::Critical,
        r::SENSITIVE_PATH_WRITE | r::PTRACE_ATTEMPT | r::MOUNT_ATTEMPT => Severity::High,
        // A denied socket is a proxy bypass attempt; a denied mach-lookup is a library probing.
        r::SANDBOX_DENIED if op.starts_with("network-") => Severity::High,
        // stat() probes up the directory tree (rg's .gitignore walk, node's
        // package.json lookup) reveal nothing; a denied *data* read is the signal.
        r::SANDBOX_DENIED if op == "file-read-metadata" => Severity::Low,
        r::SANDBOX_DENIED if op.starts_with("file-") => Severity::Medium,
        r::SANDBOX_DENIED => Severity::Low,
        r::SENSITIVE_PATH_READ | r::WORKSPACE_ESCAPE | r::HOST_RECON => Severity::Medium,
        _ => Severity::Medium,
    }
}

/// A denial of a *write* under the escape rule is only interesting when it names
/// a real path; the same rule fires constantly for `/dev/…` probes.
fn interesting(v: &Violation) -> bool {
    !IGNORED.iter().any(|n| format!("{} {}", v.op, v.path).starts_with(n) || v.process.contains(n))
}

/// Emits the alert for one (violation, tag) pair.
async fn report(reg: &Registry, v: &Violation, id: &str, rule: &str) {
    let Some(live) = reg.lock().await.get(id).cloned() else { return };
    // `system-debug` is macOS for ptrace/task_for_pid: name the attempt.
    let rule = if v.op == "system-debug" { proto::rules::PTRACE_ATTEMPT } else { rule };
    let corr = live.corr_for_pid(v.pid).await;
    let path = if v.path.is_empty() { v.op.clone() } else { v.path.clone() };
    live.ev.alert(
        &corr,
        severity(rule, &v.op),
        rule,
        format!("{} denied {} on {}", v.process, v.op, path),
        json!({"pid": v.pid, "path": path,
               "evidence": {"process": v.process, "op": v.op, "source": "seatbelt"}}),
    );
    // The same denial is also a file event, which is what the dashboard's Files
    // tab filters on.
    if v.op.starts_with("file-") {
        let op = if v.op.contains("write") { "write" } else { "read" };
        live.ev.emit(&corr, EventType::FileAccess, json!({"pid": v.pid, "path": path, "op": op, "sensitive": true}));
    }
}

/// Runs one `log stream` for the life of the daemon. Restarts it if it dies.
pub fn spawn(reg: Registry) {
    if !cfg!(target_os = "macos") {
        return;
    }
    tokio::spawn(async move {
        loop {
            if let Err(e) = run(&reg).await {
                tracing::warn!(error = %e, "seatbelt log reader stopped; restarting in 5s");
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

async fn run(reg: &Registry) -> anyhow::Result<()> {
    let mut child = tokio::process::Command::new("log")
        .args(["stream", "--style", "compact", "--predicate", &format!("eventMessage CONTAINS \"{MARKER}/\"")])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("no stdout from log stream"))?;
    tracing::info!("seatbelt violation reader attached");

    // The kernel writes the denial and its message tag as two consecutive lines,
    // so the last denial seen is the one a tag belongs to.
    let mut pending: Option<Violation> = None;
    // design: one alert per (sandbox, rule, process, op, path) per 30 s. A
    // library that retries an open in a loop would otherwise flood the timeline;
    // the count still reaches /metrics through the events counter.
    let mut recent: std::collections::HashMap<String, std::time::Instant> = Default::default();
    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines.next_line().await? {
        if line.contains("Sandbox: ") && line.contains(" deny(") {
            pending = parse_violation(&line).filter(interesting);
            continue;
        }
        if let Some((id, rule)) = parse_tag(&line) {
            if let Some(v) = pending.take() {
                let key = format!("{id}/{rule}/{}/{}/{}", v.pid, v.op, v.path);
                let now = std::time::Instant::now();
                if recent.len() > 4096 {
                    recent.retain(|_, t| now.duration_since(*t).as_secs() < 30);
                }
                if recent.get(&key).is_some_and(|t| now.duration_since(*t).as_secs() < 30) {
                    continue;
                }
                recent.insert(key, now);
                report(reg, &v, &id, &rule).await;
            }
        }
    }
    anyhow::bail!("log stream ended")
}

/// Used by `doctor`: can this daemon read the unified log at all? Without it the
/// native tier still confines, it just stops reporting.
pub async fn probe() -> bool {
    let Ok(out) = tokio::process::Command::new("log")
        .args(["show", "--last", "1m", "--style", "compact", "--predicate", "eventMessage CONTAINS \"__sbx_probe__\""])
        .output()
        .await
    else {
        return false;
    };
    out.status.success()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real lines, copied out of `log stream` on macOS 26 while a rendered
    /// profile was denying things.
    #[test]
    fn real_log_lines_parse() {
        let line =
            "2026-09-08 12:08:19.267 E  kernel[0:42486c] (Sandbox) Sandbox: git(8295) deny(1) file-read-metadata /var";
        assert_eq!(
            parse_violation(line),
            Some(Violation { process: "git".into(), pid: 8295, op: "file-read-metadata".into(), path: "/var".into() })
        );
        let line = "2026-09-08 12:08:19.271 E  kernel[0:4243d7] (Sandbox) Sandbox: git(8295) deny(1) mach-lookup com.apple.diagnosticd";
        let v = parse_violation(line).unwrap();
        assert_eq!(v.op, "mach-lookup");
        assert!(!interesting(&v), "known noise must not become an alert");

        assert_eq!(parse_tag("SBX/sbx_7f3a/canary.read"), Some(("sbx_7f3a".into(), "canary.read".into())));
        assert_eq!(parse_tag("  SBX/sbx_1/workspace.escape  "), Some(("sbx_1".into(), "workspace.escape".into())));
        assert_eq!(parse_tag("nothing here"), None);
        assert_eq!(parse_tag("SBX/"), None);
    }

    #[test]
    fn garbage_never_panics() {
        for bad in ["", "Sandbox: ", "Sandbox:  deny(", "x deny(1) ", "Sandbox: p(notanum) deny(1) op /p"] {
            let _ = parse_violation(bad);
            let _ = parse_tag(bad);
        }
        assert_eq!(
            parse_violation("Sandbox: sh(7) deny(1) network-outbound"),
            Some(Violation { process: "sh".into(), pid: 7, op: "network-outbound".into(), path: String::new() })
        );
    }

    #[test]
    fn severities_match_the_protocol_table() {
        use proto::rules as r;
        assert_eq!(severity(r::CANARY_READ, "file-read-data"), Severity::Critical);
        assert_eq!(severity(r::SENSITIVE_PATH_READ, "file-read-data"), Severity::Medium);
        assert_eq!(severity(r::WORKSPACE_ESCAPE, "file-write-create"), Severity::Medium);
        assert_eq!(severity(r::SANDBOX_DENIED, "network-outbound"), Severity::High);
        assert_eq!(severity(r::SANDBOX_DENIED, "mach-lookup"), Severity::Low);
        assert_eq!(severity(r::SANDBOX_DENIED, "file-read-metadata"), Severity::Low);
        assert_eq!(severity(r::SANDBOX_DENIED, "file-read-data"), Severity::Medium);
    }
}
