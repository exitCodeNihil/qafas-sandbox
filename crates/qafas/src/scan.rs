//! v5.2 template security scan (docs/security.md M43). One throwaway sandbox of
//! the template, booted straight on the backend like the memory-capture VM (no
//! workspace, no events, not a sandbox anyone holds), runs `images/probe/scan.sh`
//! through the ordinary `/exec` path — so as uid 1000, under the same seccomp,
//! capability set and network as an agent — and the checks it prints become the
//! template's grade. Never on the create path: after a build, once per image at
//! start for `base`, and on `POST /snapshots/{name}/scan`.

use proto::{EventType, SecurityCheck, TemplateSecurity};
use serde_json::json;

use crate::api::AppState;
use crate::events::{now_rfc3339, Corr};
use crate::snapshots::{podman_image, BASE};

const SCRIPT: &str = include_str!("../../../images/probe/scan.sh");

/// Scans `template` and records the result on it.
pub async fn run(st: &AppState, template: &str) -> anyhow::Result<TemplateSecurity> {
    let sec = scan(st, template).await?;
    st.snapshots.set_security(template, sec.clone()).await;
    Ok(sec)
}

/// Scans `template` and raises `template.insecure` when it grades `F`; the
/// caller records the result (a build sets it on the row it is about to write).
pub async fn scan(st: &AppState, template: &str) -> anyhow::Result<TemplateSecurity> {
    let backend = st.pool.backend().clone();
    let remote = match backend.name() {
        "podman" => false,
        "firecracker" => true,
        other => anyhow::bail!("the {other} tier has no templates to scan"),
    };
    let (image, snapshot) = match (template == BASE, remote) {
        (true, false) => (st.templates.image_for(&[], &st.cfg.template_image), None),
        (false, false) => (podman_image(template), None),
        (true, true) => (String::new(), None),
        (false, true) => (String::new(), Some(crate::backend::SnapshotRef { dir: st.snapshots.dir_of(template) })),
    };
    let digest = digest(st, &image, remote, template).await;
    let sb = backend
        .create(crate::backend::Spec {
            id: format!("{}scan", crate::pool::new_id()),
            template: String::new(),
            // The image's own home on the vm tier, which mounts nothing from the host;
            // a microVM gets no workspace at all, like the memory-capture VM.
            workspace_path: if remote { String::new() } else { "/home/agent".into() },
            egress_allow: Vec::new(),
            image,
            snapshot,
            env: Default::default(),
            pi_session: String::new(),
            limits: st.cfg.default_limits(),
        })
        .await?;
    let checks = exec_scan(&sb).await;
    if let Err(e) = backend.destroy(&sb).await {
        tracing::warn!(error = %e, sandbox_id = %sb.id, "scan sandbox not torn down");
    }
    let checks = checks?;
    let sec = TemplateSecurity {
        grade: proto::security_grade(&checks).to_string(),
        scanned_at: now_rfc3339(),
        image_digest: digest,
        findings: checks,
    };
    let failed: Vec<&str> = sec.findings.iter().filter(|c| !c.ok).map(|c| c.id.as_str()).collect();
    tracing::info!(template, grade = %sec.grade, ?failed, "template scanned");
    if sec.grade == "F" {
        st.emit(
            "",
            &Corr::default(),
            EventType::SecurityAlert,
            json!({
                "rule": proto::rules::TEMPLATE_INSECURE,
                "severity": "high",
                "msg": format!("template {template} failed its security scan: {}", failed.join(", ")),
                "template": template,
                "failed": failed,
            }),
        );
    }
    Ok(sec)
}

async fn exec_scan(sb: &crate::backend::Sandbox) -> anyhow::Result<Vec<SecurityCheck>> {
    use base64::Engine;
    // Base64 so the script reaches `sh` byte for byte, whatever shell `/exec` wraps it in.
    let b64 = base64::engine::general_purpose::STANDARD.encode(SCRIPT);
    let body = json!({"cmd": format!("echo {b64} | base64 -d | sh"), "cwd": "/tmp", "timeout_ms": 120_000});
    let call = crate::backend::guest_call(&sb.connector, sb.agent_token.as_deref(), "POST", "/exec", &body);
    let (status, text) = tokio::time::timeout(std::time::Duration::from_secs(150), call).await??;
    if !(200..300).contains(&status) {
        anyhow::bail!("scan exec returned {status}");
    }
    let resp: proto::ExecResp = serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap_or_default())?;
    let checks = parse(&resp.stdout);
    if checks.is_empty() {
        anyhow::bail!(
            "the scan printed no checks (exit {}): {}",
            resp.exit,
            resp.stderr.chars().take(200).collect::<String>()
        );
    }
    Ok(checks)
}

/// One JSON object per line; anything else the image's shell printed is ignored.
fn parse(stdout: &str) -> Vec<SecurityCheck> {
    stdout.lines().filter_map(|l| serde_json::from_str(l.trim()).ok()).collect()
}

/// What was scanned, so `base` is rescanned only when its bits change.
async fn digest(st: &AppState, image: &str, remote: bool, template: &str) -> String {
    if !remote {
        // The runtime's image id, through its socket (no CLI on a containerised
        // worker); unreadable, it keys on the daemon version and rescans per upgrade.
        let id = crate::backend::podman::image_inspect(image).await.and_then(|i| i["Id"].as_str().map(String::from));
        return format!("{image}@{}", id.unwrap_or_else(|| format!("qafas-{}", proto::VERSION)));
    }
    let file = match template {
        BASE => st.cfg.fc_rootfs.clone(),
        t => st.snapshots.dir_of(t).join("rootfs.ext4").display().to_string(),
    };
    let m = std::fs::metadata(&file);
    let mtime =
        m.as_ref().ok().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
    format!("{file}:{}:{}", m.map(|m| m.len()).unwrap_or(0), mtime.map(|d| d.as_secs()).unwrap_or(0))
}

/// Daemon start: scan `base` unless the cached result is for these same bits.
pub async fn ensure_base(st: &AppState) {
    if !matches!(st.pool.backend().name(), "podman" | "firecracker") {
        return;
    }
    let remote = st.pool.backend().name() == "firecracker";
    let image = if remote { String::new() } else { st.templates.image_for(&[], &st.cfg.template_image) };
    let current = digest(st, &image, remote, BASE).await;
    let cached = st.snapshots.get(BASE).await.and_then(|b| b.security).map(|s| s.image_digest);
    if cached.as_deref() == Some(current.as_str()) {
        tracing::info!("base security scan is current");
        return;
    }
    if let Err(e) = run(st, BASE).await {
        tracing::warn!(error = %e, "base security scan failed; base keeps no grade");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_keeps_json_lines_and_skips_noise() {
        let out = "motd noise\n{\"id\":\"caps\",\"class\":\"boundary\",\"ok\":true,\"detail\":\"CapEff=0\"}\n\
                   {\"id\":\"setid_files\",\"class\":\"hygiene\",\"ok\":false,\"detail\":\"x\"}\nnot json {\n";
        let c = super::parse(out);
        assert_eq!(c.len(), 2);
        assert_eq!((c[0].id.as_str(), c[0].ok, c[1].ok), ("caps", true, false));
        assert_eq!(proto::security_grade(&c), "B");
    }

    #[test]
    fn the_script_is_embedded_and_covers_every_boundary_check() {
        for id in [
            "caps",
            "no_new_privs",
            "seccomp",
            "mount",
            "userns",
            "runtime_socket",
            "egress_direct",
            "metadata",
            "dns",
            "env_llm_keys",
            "pid1_environ",
        ] {
            assert!(super::SCRIPT.contains(&format!("out {id} boundary")), "{id}");
        }
    }
}
