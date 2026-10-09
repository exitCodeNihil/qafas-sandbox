//! The persisted sandbox table: one `<state_dir>/sandboxes/<id>.json` per live
//! sandbox, written at every state change.
//!
//! Everything else about a sandbox lives in memory, which is why a `stopped` or
//! `archived` microVM — whose whole purpose is surviving time — used to be swept
//! by the next daemon start. With the
//! table, start re-adopts them and the sweep only reaps what has no owner.
//!
//! Never the agent token: a record is a plain file under the state dir, and the
//! only tier that mints one (podman) is not re-adopted anyway.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use proto::{Isolation, SandboxState};
use serde::{Deserialize, Serialize};

use crate::api::Live;
use crate::config::Config;

/// What `api::Live` needs to be rebuilt at the next start. Every field is
/// either a client's request or a clock; nothing here is a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRecord {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub template: String,
    pub isolation: Isolation,
    /// `Backend::name()`, so the plan can tell a microVM from a container.
    pub backend: String,
    pub workspace_path: String,
    #[serde(default)]
    pub pi_session: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub created_ms: i64,
    pub created_at: String,
    pub state: SandboxState,
    pub state_changed_ms: i64,
    pub auto_stop_secs: Option<u64>,
    pub auto_archive_secs: Option<u64>,
    pub auto_delete_secs: Option<u64>,
    pub max_age_secs: Option<u64>,
    pub ttl_secs: u64,
    /// design: written at state changes only, not on every request — so after
    /// a restart idleness restarts from now. The timer that matters for a
    /// stopped sandbox (`auto_delete`) counts from `state_changed_ms`, which is
    /// exact. Persist it per request only if idle accounting has to survive too.
    pub last_activity_ms: i64,
    /// The guest address, which is also its /30 slot (`slot_of`).
    pub peer_ip: Option<IpAddr>,
    /// v4d. Set only by `api::shutdown`, on a sandbox it stopped because the
    /// daemon was going down: the next start restores it instead of leaving it
    /// stopped. Never derived from a `Live`, so every other write clears it and
    /// a sandbox the client stopped on purpose stays stopped.
    #[serde(default)]
    pub resume_on_start: bool,
    /// v5 §3a. So a re-adopted sandbox comes back under the ceilings it was
    /// created with. Absent in a record a pre-v5 daemon wrote: that sandbox was
    /// running the default size, which is what `adopt` then gives it.
    #[serde(default)]
    pub size: String,
    #[serde(default)]
    pub limits: Option<proto::SandboxLimits>,
}

impl From<&Live> for LiveRecord {
    fn from(l: &Live) -> Self {
        Self {
            id: l.sb.id.clone(),
            name: l.name.clone(),
            labels: l.labels.clone(),
            template: l.sb.template.clone(),
            isolation: l.isolation,
            backend: l.backend.name().to_string(),
            workspace_path: l.sb.workspace_path.clone(),
            pi_session: l.pi_session.clone(),
            env: l.env.clone(),
            created_ms: l.created_ms,
            created_at: l.sb.created_at.clone(),
            state: l.state(),
            state_changed_ms: l.changed_ms(),
            auto_stop_secs: l.auto_stop_secs,
            auto_archive_secs: l.auto_archive_secs,
            auto_delete_secs: l.auto_delete_secs,
            max_age_secs: l.max_age_secs,
            ttl_secs: l.ttl_secs,
            last_activity_ms: l.last_activity.load(std::sync::atomic::Ordering::Relaxed),
            peer_ip: l.sb.peer_ip,
            // A property of *why* the daemon stopped it, which a `Live` does not
            // know: `shutdown` sets it on the record it writes, nobody else.
            resume_on_start: false,
            size: l.size.clone(),
            limits: Some(l.limits),
        }
    }
}

pub fn dir(cfg: &Config) -> PathBuf {
    PathBuf::from(&cfg.state_dir).join("sandboxes")
}

fn path(cfg: &Config, id: &str) -> PathBuf {
    dir(cfg).join(format!("{id}.json"))
}

/// Write through a temp file in the same directory: a crash mid-write leaves
/// either the old record or the new one, never half of one.
pub fn write(cfg: &Config, l: &Live) -> std::io::Result<()> {
    write_rec(cfg, &LiveRecord::from(l))
}

/// The same, for the one caller with a record a `Live` cannot produce
/// (`api::shutdown`'s `resume_on_start`).
pub fn write_rec(cfg: &Config, rec: &LiveRecord) -> std::io::Result<()> {
    let d = dir(cfg);
    std::fs::create_dir_all(&d)?;
    let tmp = d.join(format!(".{}.json.tmp", rec.id));
    let body = serde_json::to_vec_pretty(rec)?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path(cfg, &rec.id))
}

pub fn forget(cfg: &Config, id: &str) -> std::io::Result<()> {
    match std::fs::remove_file(path(cfg, id)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

pub fn load_all(cfg: &Config) -> Vec<LiveRecord> {
    let d = dir(cfg);
    let Ok(rd) = std::fs::read_dir(&d) else { return Vec::new() };
    let mut out = Vec::new();
    for e in rd.flatten() {
        if e.path().extension().is_none_or(|x| x != "json") {
            continue;
        }
        match std::fs::read_to_string(e.path()).ok().and_then(|s| serde_json::from_str(&s).ok()) {
            Some(r) => out.push(r),
            None => tracing::warn!(file = %e.path().display(), "unreadable sandbox record"),
        }
    }
    out
}

// ---- the Firecracker layout, here rather than in `backend::firecracker`,
// because `plan` runs before the backend exists and on hosts that have none.

/// The jailer only accepts `[A-Za-z0-9-]` ids; our ids carry an underscore.
pub fn jail_id(id: &str) -> String {
    id.replace('_', "-")
}

pub fn jail_dir(cfg: &Config, id: &str) -> PathBuf {
    PathBuf::from(&cfg.fc_jail_dir).join("firecracker").join(jail_id(id))
}

pub fn jail_root(cfg: &Config, id: &str) -> PathBuf {
    jail_dir(cfg, id).join("root")
}

/// Where `archive` parks `snap/` plus the two images the restore needs.
pub fn archive_dir(cfg: &Config, id: &str) -> PathBuf {
    PathBuf::from(&cfg.fc_archive_dir).join(jail_id(id))
}

/// Which records the next start can take back, and which are only litter.
///
/// A record is adoptable when it is a microVM that is *meant* to have no
/// process (`stopped`, `archived`) and the files a restore needs are still
/// there. Everything else — a `ready` record (its VM died with the daemon), a
/// container, a record whose jail was swept by hand — is dropped: the caller
/// forgets it and reports it destroyed.
///
/// `exists` is a parameter so the whole decision is testable off a real host.
pub fn plan(
    cfg: &Config,
    records: Vec<LiveRecord>,
    exists: impl Fn(&Path) -> bool,
) -> (Vec<LiveRecord>, Vec<LiveRecord>) {
    let (mut adopt, mut gone) = (Vec::new(), Vec::new());
    for r in records {
        let keep = r.backend == "firecracker"
            && match r.state {
                SandboxState::Stopped => {
                    let root = jail_root(cfg, &r.id);
                    exists(&root.join("snap/vmstate")) && exists(&root.join("rootfs.ext4"))
                }
                SandboxState::Archived => exists(&archive_dir(cfg, &r.id).join("vmstate")),
                _ => false,
            };
        if keep {
            adopt.push(r);
        } else {
            gone.push(r);
        }
    }
    (adopt, gone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileConfig;

    fn cfg(tag: &str) -> Config {
        let mut c = Config::resolve(FileConfig::default());
        let root = std::env::temp_dir().join(format!("sbx-lt-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        c.state_dir = root.display().to_string();
        c.fc_jail_dir = root.join("jail").display().to_string();
        c.fc_archive_dir = root.join("archive").display().to_string();
        c
    }

    fn rec(id: &str, backend: &str, state: SandboxState) -> LiveRecord {
        LiveRecord {
            id: id.into(),
            name: id.into(),
            labels: BTreeMap::new(),
            template: "base".into(),
            isolation: Isolation::Remote,
            backend: backend.into(),
            workspace_path: "/w".into(),
            pi_session: "s1".into(),
            env: BTreeMap::new(),
            created_ms: 1,
            created_at: "2026-09-11T00:00:00.000Z".into(),
            state,
            state_changed_ms: 2,
            auto_stop_secs: Some(30),
            auto_archive_secs: None,
            auto_delete_secs: Some(600),
            max_age_secs: None,
            ttl_secs: 900,
            last_activity_ms: 3,
            peer_ip: "172.16.9.2".parse().ok(),
            resume_on_start: false,
            size: "mini".into(),
            limits: Some(proto::sizes::default_table()["mini"]),
        }
    }

    /// A record survives the round trip through the directory, and `forget`
    /// takes it out again.
    #[test]
    fn a_record_round_trips_through_the_state_dir() {
        let c = cfg("rt");
        let mut r = rec("sbx_a1", "firecracker", SandboxState::Stopped);
        r.resume_on_start = true;
        std::fs::create_dir_all(dir(&c)).unwrap();
        std::fs::write(path(&c, &r.id), serde_json::to_vec(&r).unwrap()).unwrap();
        // An unreadable file is skipped, not fatal.
        std::fs::write(dir(&c).join("junk.json"), b"{nope").unwrap();

        let all = load_all(&c);
        assert_eq!(all.len(), 1, "the junk record is skipped: {all:?}");
        let got = &all[0];
        assert_eq!(got.id, "sbx_a1");
        assert_eq!(got.state, SandboxState::Stopped);
        assert_eq!(got.state_changed_ms, 2, "auto_delete counts from the original stop");
        assert_eq!(got.peer_ip, "172.16.9.2".parse().ok(), "the slot comes back with the record");
        assert_eq!(got.ttl_secs, 900);
        assert!(got.resume_on_start, "the park flag survives, so the next start restores it");
        // A record written before v4d has no such field and reads as "not parked".
        let old = serde_json::json!({"id":"x","name":"x","template":"base","isolation":"remote",
            "backend":"firecracker","workspace_path":"/w","created_ms":1,
            "created_at":"2026-09-11T00:00:00.000Z","state":"stopped","state_changed_ms":2,
            "auto_stop_secs":null,"auto_archive_secs":null,"auto_delete_secs":null,
            "max_age_secs":null,"ttl_secs":900,"last_activity_ms":3,"peer_ip":null});
        let old: LiveRecord = serde_json::from_value(old).expect("a v4c record still parses");
        assert!(!old.resume_on_start);

        forget(&c, "sbx_a1").unwrap();
        assert!(load_all(&c).is_empty());
        forget(&c, "sbx_a1").unwrap(); // idempotent
        let _ = std::fs::remove_dir_all(&c.state_dir);
    }

    /// §3 of the lifecycle doc: only a microVM that is meant to have no process
    /// and still has its files comes back.
    #[test]
    fn only_stopped_and_archived_microvms_with_their_files_are_adopted() {
        let c = cfg("plan");
        let stopped = rec("sbx_stop", "firecracker", SandboxState::Stopped);
        let no_vmstate = rec("sbx_nofiles", "firecracker", SandboxState::Stopped);
        let archived = rec("sbx_arch", "firecracker", SandboxState::Archived);
        let ready = rec("sbx_ready", "firecracker", SandboxState::Ready);
        let container = rec("sbx_pod", "podman", SandboxState::Stopped);

        let have = [
            jail_root(&c, "sbx_stop").join("snap/vmstate"),
            jail_root(&c, "sbx_stop").join("rootfs.ext4"),
            // The stopped sandbox whose jail was swept has its rootfs but no snapshot.
            jail_root(&c, "sbx_nofiles").join("rootfs.ext4"),
            archive_dir(&c, "sbx_arch").join("vmstate"),
            jail_root(&c, "sbx_ready").join("snap/vmstate"),
            jail_root(&c, "sbx_ready").join("rootfs.ext4"),
        ];
        let exists = |p: &Path| have.iter().any(|h| h == p);

        let (adopt, gone) = plan(&c, vec![stopped, no_vmstate, archived, ready, container], exists);
        let ids = |v: &[LiveRecord]| v.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&adopt), ["sbx_stop", "sbx_arch"], "adopted");
        assert_eq!(ids(&gone), ["sbx_nofiles", "sbx_ready", "sbx_pod"], "dropped");
    }

    #[test]
    fn the_jail_layout_matches_the_backends() {
        let c = cfg("paths");
        assert_eq!(jail_id("sbx_a1"), "sbx-a1");
        assert!(jail_root(&c, "sbx_a1").ends_with("firecracker/sbx-a1/root"));
        assert!(archive_dir(&c, "sbx_a1").ends_with("archive/sbx-a1"));
    }
}
