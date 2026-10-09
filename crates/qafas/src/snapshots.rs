//! v3 snapshots (protocol §3a): a named thing a sandbox can be created from.
//!
//! Two kinds, and the difference is the whole point:
//!   * `image` — a filesystem only (an OCI image on the vm tier, an ext4 on the
//!     remote tier). A sandbox made from it boots.
//!   * `vm`    — memory *and* filesystem, captured from a live microVM. A
//!     sandbox made from it is a restore, which is what makes it sub-100 ms.
//!
//! State lives in `$SBX_STATE_DIR/snapshots/<name>.json`, the bytes in
//! `$SBX_STATE_DIR/snapshots/<name>/`. One file per snapshot so a half-written
//! one cannot corrupt the rest.

use std::collections::BTreeMap;
use std::path::PathBuf;

use proto::{EventType, SnapshotInfo, SnapshotSource, SnapshotState};
use serde_json::json;
use tokio::sync::Mutex;

use crate::api::AppState;
use crate::backend::podman::{
    image_build, image_commit, image_export, image_inspect, image_pull, image_remove, image_tag,
    remove_build_containers,
};
use crate::events::{now_rfc3339, Corr};

pub struct Store {
    dir: PathBuf,
    /// design: the whole index under one lock. It is read once per create and
    /// written once per build; contention is not a thing that can happen here.
    map: Mutex<BTreeMap<String, SnapshotInfo>>,
    /// §3a: the built-in image is listed as an `active` `image` row named `base`,
    /// so a client can see every template from one place. It is synthetic: never
    /// on disk, never claimable, never deletable.
    base: SnapshotInfo,
    /// v4: the one mutable thing about `base` (`PUT /snapshots/base {warm}`).
    /// A number in `base.warm`, not a record, so the loader keeps ignoring it.
    base_warm: Mutex<u32>,
    /// v5.2: `base`'s last security scan, kept beside `base.warm` for the same
    /// reason — the row itself is synthetic.
    base_security: Mutex<Option<proto::TemplateSecurity>>,
    /// v4c: the host's pooled tier (`remote`|`vm`, empty on a native-only host).
    /// Every template here is a template of that runtime, so it is stamped on
    /// the way out rather than stored per row — a record written by an older
    /// daemon then reads back with the right runtime too.
    pub runtime: String,
}

/// The name reserved for the built-in image.
pub const BASE: &str = "base";

fn base_row(cfg: &crate::config::Config) -> SnapshotInfo {
    let source = match cfg.primary_backend() {
        // The rootfs file is the image on a Firecracker host; its basename is the
        // only part a human recognises.
        "firecracker" => cfg.fc_rootfs.rsplit('/').next().unwrap_or(&cfg.fc_rootfs).to_string(),
        _ => cfg.template_image.clone(),
    };
    SnapshotInfo {
        name: BASE.into(),
        state: SnapshotState::Active,
        kind: "image".into(),
        source: SnapshotSource { image: Some(source), ..Default::default() },
        created_at: now_rfc3339(),
        bytes: 0,
        error: None,
        host_id: None,
        warm: cfg.pool_size,
        memory_snapshot: false,
        warm_ready: 0,
        runtime: String::new(),
        security: None,
    }
}

/// `[a-z0-9][a-z0-9._-]{0,63}`: it is also a `template` and a podman image tag.
pub fn valid_name(name: &str) -> bool {
    let mut cs = name.chars();
    cs.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
}

/// An image reference without a tag, or tagged `latest`, means "whatever the
/// registry has today" — which is not a snapshot. `400`, per §3a.
pub fn check_image_ref(r: &str) -> Result<(), String> {
    let last = r.rsplit('/').next().unwrap_or(r);
    if last.contains('@') {
        return Ok(()); // digest-pinned
    }
    match last.rsplit_once(':') {
        None => Err(format!("{r} has no tag; a snapshot must pin one")),
        Some((_, "latest")) => Err(format!("{r} is tagged latest, which is not a fixed image")),
        Some(_) => Ok(()),
    }
}

impl Store {
    pub fn load(cfg: &crate::config::Config, runtime: &str) -> Self {
        let dir = PathBuf::from(&cfg.state_dir).join("snapshots");
        let _ = std::fs::create_dir_all(&dir);
        let mut map = BTreeMap::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                // `base.security.json` is the scan cache (scan.rs), not a record.
                let name = e.file_name().to_string_lossy().into_owned();
                if !name.ends_with(".json") || name.ends_with(".security.json") {
                    continue;
                }
                match std::fs::read_to_string(e.path()).ok().and_then(|s| serde_json::from_str::<SnapshotInfo>(&s).ok())
                {
                    // A `building` row in a file means the daemon died mid-build;
                    // there is no build to resume, so it is an error, not a lie.
                    Some(mut i) => {
                        if i.state == SnapshotState::Building {
                            i.state = SnapshotState::Error;
                            i.error = Some("the daemon restarted while this was building".into());
                        }
                        map.insert(i.name.clone(), i);
                    }
                    None => tracing::warn!(file = %e.path().display(), "unreadable snapshot record"),
                }
            }
        }
        // A record named `base` would shadow the built-in row and can only come
        // from an older daemon; drop it rather than serve two answers.
        map.remove(BASE);
        tracing::info!(snapshots = map.len(), dir = %dir.display(), "snapshot store");
        let base_warm = std::fs::read_to_string(dir.join("base.warm"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(cfg.pool_size);
        let base_security =
            std::fs::read_to_string(dir.join("base.security.json")).ok().and_then(|s| serde_json::from_str(&s).ok());
        Self {
            dir,
            map: Mutex::new(map),
            base: base_row(cfg),
            base_warm: Mutex::new(base_warm),
            base_security: Mutex::new(base_security),
            runtime: runtime.to_string(),
        }
    }

    /// v4c: the host's runtime on the way out of the store.
    pub fn stamp(&self, mut i: SnapshotInfo) -> SnapshotInfo {
        i.runtime = self.runtime.clone();
        i
    }

    /// The `base` row as it is right now: its `warm` and whether the daemon has
    /// captured its memory yet.
    async fn base_now(&self) -> SnapshotInfo {
        let mut b = self.stamp(self.base.clone());
        b.warm = *self.base_warm.lock().await;
        b.memory_snapshot = has_memory(&self.dir_of(BASE));
        b.security = self.base_security.lock().await.clone();
        b
    }

    /// v5.2: records a finished scan. `None` = no such template on this host (it
    /// may have been deleted while the scan ran).
    pub async fn set_security(&self, name: &str, sec: proto::TemplateSecurity) -> Option<SnapshotInfo> {
        if name == BASE {
            let _ = serde_json::to_vec_pretty(&sec).map(|b| std::fs::write(self.dir.join("base.security.json"), b));
            *self.base_security.lock().await = Some(sec);
            return Some(self.base_now().await);
        }
        let info = {
            let mut g = self.map.lock().await;
            let i = g.get_mut(name)?;
            i.security = Some(sec);
            i.clone()
        };
        self.persist(&info);
        Some(self.stamp(info))
    }

    /// v4 `PUT /snapshots/{name}`: the only mutable field. `None` = no such
    /// snapshot on this host.
    pub async fn set_warm(&self, name: &str, warm: u32) -> Option<SnapshotInfo> {
        if name == BASE {
            *self.base_warm.lock().await = warm;
            let _ = std::fs::write(self.dir.join("base.warm"), warm.to_string());
            return Some(self.base_now().await);
        }
        let info = {
            let mut g = self.map.lock().await;
            let i = g.get_mut(name)?;
            i.warm = warm;
            i.clone()
        };
        self.persist(&info);
        Some(self.stamp(info))
    }

    /// Every template's `warm`, for the pool to load at start.
    pub async fn warm_targets(&self) -> Vec<(String, u32)> {
        let mut v = vec![(BASE.to_string(), *self.base_warm.lock().await)];
        v.extend(self.map.lock().await.values().map(|i| (i.name.clone(), i.warm)));
        v
    }

    pub fn dir_of(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub async fn list(&self) -> Vec<SnapshotInfo> {
        let mut v = vec![self.base_now().await];
        v.extend(self.map.lock().await.values().map(|i| self.stamp(i.clone())));
        v
    }

    pub async fn get(&self, name: &str) -> Option<SnapshotInfo> {
        if name == BASE {
            return Some(self.base_now().await);
        }
        self.map.lock().await.get(name).cloned().map(|i| self.stamp(i))
    }

    /// Claims the name. `false` means it is taken (→ `409`).
    pub async fn claim(&self, info: &SnapshotInfo) -> bool {
        if info.name == BASE {
            return false;
        }
        let mut g = self.map.lock().await;
        if g.contains_key(&info.name) {
            return false;
        }
        g.insert(info.name.clone(), info.clone());
        self.persist(info);
        true
    }

    pub async fn update(&self, info: SnapshotInfo) {
        self.persist(&info);
        self.map.lock().await.insert(info.name.clone(), info);
    }

    /// Is this name still claimed? The build asks before writing its finished
    /// row: a `DELETE` that ran while it worked took the name out of the map, and
    /// a row written after that would resurrect the template the client deleted
    /// and block its name until a second `DELETE`.
    pub async fn still_claimed(&self, name: &str) -> bool {
        self.map.lock().await.contains_key(name)
    }

    pub async fn remove(&self, name: &str) -> bool {
        let prev = self.map.lock().await.remove(name);
        // Deleting a `building` row is the cancel: kill the export container the
        // build is feeding so it stops now rather than finishing into a template
        // nobody holds. `still_claimed` discards whatever it wrote.
        if prev.as_ref().is_some_and(|i| i.state == SnapshotState::Building) {
            rm_build_containers(name);
        }
        let _ = std::fs::remove_file(self.dir.join(format!("{name}.json")));
        let _ = std::fs::remove_dir_all(self.dir_of(name));
        prev.is_some()
    }

    fn persist(&self, info: &SnapshotInfo) {
        let path = self.dir.join(format!("{}.json", info.name));
        if let Err(e) =
            serde_json::to_vec_pretty(info).map_err(std::io::Error::other).and_then(|b| std::fs::write(&path, b))
        {
            tracing::error!(error = %e, file = %path.display(), "snapshot record not written");
        }
    }
}

// -------------------------------------------------- v4 template memory snapshots

/// A capture is `vmstate` + `mem` beside the rootfs. Both or neither: a
/// half-written pair must read as "no capture", or every restore fails.
pub fn has_memory(dir: &std::path::Path) -> bool {
    dir.join("vmstate").exists() && dir.join("mem").exists()
}

/// v4 §3a "start is a restore": boot this rootfs once, wait for the guest and
/// its page-cache warm-up, photograph the memory next to the rootfs, throw the
/// VM away. The sandbox this boots is never handed out — it exists to be
/// photographed — so it gets no workspace, no egress and no events.
///
/// `snapshot` is `None` for the built-in rootfs and `Some(image ref)` for a
/// freshly built one. Returns the captured bytes.
pub async fn capture_memory(
    st: &AppState,
    dir: PathBuf,
    snapshot: Option<crate::backend::SnapshotRef>,
) -> anyhow::Result<u64> {
    let backend = st.pool.backend().clone();
    if backend.name() != "firecracker" {
        anyhow::bail!("memory snapshots need the remote tier");
    }
    // Firecracker's file memory backend cannot restore a hugetlbfs-backed guest
    // ("Please use uffd", measured on 1.15), so a capture on such a host would
    // produce an image nothing can start. Boot as before instead (docs/deployment.md
    // 5.4; a UFFD handler is the upgrade).
    if st.cfg.fc_hugepages {
        anyhow::bail!("SBX_FC_HUGEPAGES is on; a hugetlbfs guest cannot be restored from a memory file");
    }
    let sb = backend
        .create(crate::backend::Spec {
            id: format!("{}cap", crate::pool::new_id()),
            template: String::new(),
            workspace_path: String::new(),
            egress_allow: Vec::new(),
            image: String::new(),
            snapshot,
            env: Default::default(),
            pi_session: String::new(),
            // The capture VM is a throwaway that only warms a page cache.
            limits: st.cfg.default_limits(),
        })
        .await?;
    let r = async {
        warm_guest(&sb.connector).await;
        backend.snapshot(&sb, dir.clone()).await
    }
    .await;
    // Whatever happened, the throwaway does not outlive this function.
    if let Err(e) = backend.destroy(&sb).await {
        tracing::warn!(error = %e, sandbox_id = %sb.id, "capture VM not torn down");
    }
    if r.is_err() {
        // Half a capture must not read as one: `has_memory` is what every
        // create consults. The rootfs beside it is the build's, so it stays.
        for f in ["vmstate", "mem"] {
            let _ = std::fs::remove_file(dir.join(f));
        }
    }
    r
}

/// The guest warms its own page cache at init, but in the background: a
/// snapshot taken before that finishes photographs a cold VM and every restore
/// pays the 120 MB of virtio-blk reads again. Running the same commands through
/// `/exec` waits for exactly that (the second run is all page-cache hits).
async fn warm_guest(conn: &crate::backend::Connector) {
    let body = json!({"cmd": proto::WARM_CMD, "cwd": "/tmp"});
    // Firecracker only, and vsock carries no token (§2).
    let call = crate::backend::guest_call(conn, None, "POST", "/exec", &body);
    match tokio::time::timeout(std::time::Duration::from_secs(60), call).await {
        Ok(Ok((status, _))) if (200..300).contains(&status) => {}
        Ok(Ok((status, _))) => tracing::warn!(status, "warm-up exec before the memory capture failed"),
        Ok(Err(e)) => tracing::warn!(error = %e, "warm-up exec before the memory capture failed"),
        Err(_) => tracing::warn!("warm-up exec before the memory capture timed out"),
    }
}

/// True when `dir` holds a capture at least as new as every input.
fn capture_is_current(dir: &std::path::Path, inputs: &[&str]) -> bool {
    let Ok(taken) = std::fs::metadata(dir.join("vmstate")).and_then(|m| m.modified()) else {
        return false;
    };
    has_memory(dir) && inputs.iter().all(|p| std::fs::metadata(p).and_then(|m| m.modified()).is_ok_and(|t| t <= taken))
}

/// v4 §3a: `base` starts as a restore too. Called once at daemon start; the
/// capture lives in the state dir beside every other snapshot and is rebuilt
/// whenever the rootfs or the kernel is newer than it.
pub async fn ensure_base_memory(st: &AppState) {
    if !st.cfg.base_memory_snapshot || st.pool.backend().name() != "firecracker" {
        return;
    }
    let dir = st.snapshots.dir_of(BASE);
    if capture_is_current(&dir, &[&st.cfg.fc_rootfs, &st.cfg.fc_kernel]) {
        tracing::info!(dir = %dir.display(), "base memory snapshot is current");
        return;
    }
    if st.cfg.fc_hugepages {
        tracing::warn!(
            "SBX_FC_HUGEPAGES is on: skipping the base memory snapshot, base boots as before \
             (SBX_FC_HUGEPAGES=0 trades nested-KVM fault speed for restores)"
        );
        return;
    }
    // A stale capture must not survive a failed rebuild: a restore from it would
    // hand out a sandbox running the previous rootfs.
    let _ = std::fs::remove_dir_all(&dir);
    match capture_memory(st, dir.clone(), None).await {
        Ok(bytes) => tracing::info!(bytes, dir = %dir.display(), "base memory snapshot captured"),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            tracing::warn!(error = %e, "no base memory snapshot; base sandboxes boot as before");
        }
    }
}

/// The image a podman snapshot resolves to, and the `template` a create names.
pub fn podman_image(name: &str) -> String {
    format!("localhost/sbx-snap-{name}")
}

/// The one directory a template build works in. Deterministic rather than
/// `mktemp -d`, so a daemon killed mid-build leaves something with a name the
/// next start — and the template's `DELETE` — knows how to sweep.
pub fn build_dir(cfg: &crate::config::Config, name: &str) -> PathBuf {
    PathBuf::from(&cfg.state_dir).join("build").join(name)
}

/// Removes a directory on every way out, `?` included.
struct RmOnDrop(PathBuf);

impl Drop for RmOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Removes every export container labelled for `name` (empty: all of them).
/// Best effort — no container runtime on this host is not an error here.
fn rm_build_containers(name: &str) {
    let name = name.to_string();
    tokio::spawn(async move {
        let n = remove_build_containers(&name).await;
        if n > 0 {
            tracing::warn!(containers = n, "removed template build containers");
        }
    });
}

/// Called once at daemon start. A build interrupted by a crash leaves its work
/// tree (~1.2 GB for a node image) and the `podman create`d export container
/// behind, because the shell's `trap` dies with the process group.
pub fn sweep_builds(cfg: &crate::config::Config) {
    let mut dirs = 0;
    if let Ok(rd) = std::fs::read_dir(PathBuf::from(&cfg.state_dir).join("build")) {
        for e in rd.flatten() {
            let _ = std::fs::remove_dir_all(e.path());
            dirs += 1;
        }
    }
    if dirs > 0 {
        tracing::warn!(dirs, "removed template build directories left by a previous run");
    }
    rm_build_containers("");
}

fn sh(script: &str) -> anyhow::Result<String> {
    let out = std::process::Command::new("sh").arg("-c").arg(script).output()?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr).trim().chars().take(400).collect::<String>());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Builds in the background and moves the row `building → active | error`.
pub fn spawn_build(st: AppState, mut info: SnapshotInfo, source: SnapshotSource) {
    tokio::spawn(async move {
        st.emit("", &Corr::default(), EventType::SnapshotBuilding, json!({"name": info.name}));
        let r = build(&st, &info.name, &source).await;
        match r {
            Ok((kind, mut bytes)) => {
                // v4 §3a: a `vm` snapshot *is* a memory capture; an `image` one
                // gets a throwaway boot so that every sandbox from it restores.
                // Failing that is not a failed build — it is a template that
                // boots, which is what v3 did.
                info.memory_snapshot = if kind == "vm" {
                    true
                } else if info.memory_snapshot {
                    let dir = st.snapshots.dir_of(&info.name);
                    let r = capture_memory(&st, dir.clone(), Some(crate::backend::SnapshotRef { dir })).await;
                    match r {
                        Ok(n) => {
                            bytes += n;
                            true
                        }
                        Err(e) => {
                            tracing::warn!(snapshot = %info.name, error = %e,
                                           "no memory snapshot; this template boots");
                            false
                        }
                    }
                } else {
                    false
                };
                // v5.2: graded before it goes active, so no create sees it ungraded.
                // A scan that cannot run leaves it ungraded, not unusable.
                info.security = match crate::scan::scan(&st, &info.name).await {
                    Ok(sec) => Some(sec),
                    Err(e) => {
                        tracing::warn!(snapshot = %info.name, error = %e, "template security scan failed; no grade");
                        None
                    }
                };
                info.state = SnapshotState::Active;
                info.kind = kind;
                info.bytes = bytes;
                st.emit("", &Corr::default(), EventType::SnapshotReady, json!({"name": info.name, "bytes": bytes}));
                tracing::info!(snapshot = %info.name, kind = %info.kind, bytes,
                               memory_snapshot = info.memory_snapshot, "snapshot ready");
            }
            Err(e) => {
                info.state = SnapshotState::Error;
                info.error = Some(e.to_string());
                let _ = std::fs::remove_dir_all(st.snapshots.dir_of(&info.name));
                st.emit(
                    "",
                    &Corr::default(),
                    EventType::SnapshotError,
                    json!({"name": info.name, "msg": e.to_string()}),
                );
                tracing::warn!(snapshot = %info.name, error = %e, "snapshot build failed");
            }
        }
        // A `DELETE` while this was building took the name out of the store, and
        // that is the only cancel there is. Writing the finished row now would
        // resurrect the template the client deleted and block its name.
        if !st.snapshots.still_claimed(&info.name).await {
            let _ = std::fs::remove_dir_all(st.snapshots.dir_of(&info.name));
            let _ = std::fs::remove_dir_all(build_dir(&st.cfg, &info.name));
            forget_podman_image(&info.name);
            tracing::warn!(snapshot = %info.name, "build of this template was deleted while running, discarded");
            return;
        }
        st.snapshots.update(info).await;
    });
}

/// Returns `(kind, bytes)`.
async fn build(st: &AppState, name: &str, src: &SnapshotSource) -> anyhow::Result<(String, u64)> {
    let backend = st.pool.backend().name().to_string();
    let dir = st.snapshots.dir_of(name);

    // A snapshot of a live sandbox: the only source that needs the sandbox
    // itself, and on the remote tier the only one that captures memory.
    if let Some(sid) = &src.sandbox_id {
        let live = st.live_get(sid).await.ok_or_else(|| anyhow::anyhow!("no sandbox {sid}"))?;
        return match live.backend.name() {
            "podman" => {
                image_commit(&format!("sbx-{sid}"), &podman_image(name)).await?;
                Ok(("image".to_string(), image_bytes(name).await))
            }
            "firecracker" => {
                let bytes = live.backend.snapshot(&live.sb, dir).await?;
                Ok(("vm".to_string(), bytes))
            }
            other => anyhow::bail!("the {other} tier cannot snapshot a sandbox"),
        };
    }

    // Otherwise it is an image: pulled or built, then either tagged (podman) or
    // turned into an ext4 the microVMs boot (firecracker).
    let bd = build_dir(&st.cfg, name);
    let (name, image, dockerfile, ga, size_mb) = (
        name.to_string(),
        src.image.clone(),
        src.dockerfile.clone(),
        st.cfg.guest_agent_bin.clone(),
        st.cfg.snapshot_rootfs_mb,
    );
    if image.is_none() && dockerfile.is_none() {
        anyhow::bail!("source needs one of image, dockerfile or sandbox_id");
    }
    if let Some(r) = &image {
        check_image_ref(r).map_err(|e| anyhow::anyhow!(e))?;
    }
    // The image, pulled or built through the runtime's socket on both tiers: no
    // CLI is needed, so a worker can run as a container, and the privileged work
    // happens in the runtime's own service (backend/podman.rs, image ops).
    let tag = podman_image(&name);
    match (&image, &dockerfile) {
        (Some(r), _) => {
            image_pull(r).await?;
            image_tag(r, &tag).await?;
        }
        (None, Some(df)) => image_build(df, &tag).await?,
        _ => unreachable!("checked above"),
    }
    if backend != "firecracker" {
        return Ok(("image".to_string(), image_bytes(&name).await));
    }

    // The remote tier boots an ext4, not an image: the same export + `mkfs.ext4
    // -d` that images/build-rootfs.sh does. One work dir for the whole build,
    // created fresh: whatever a previous attempt or a killed daemon left is not
    // part of this one. `RmOnDrop` takes it away again on every path out of here.
    let _ = std::fs::remove_dir_all(&bd);
    let root = bd.join("root");
    std::fs::create_dir_all(&root)?;
    let _rm = RmOnDrop(bd.clone());
    image_export(&tag, &name, &root).await?;
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&dir)?;
        let rootfs = dir.join("rootfs.ext4");
        // The image is a user's, so it has no guest-agent unless we put one in:
        // SBX_GUEST_AGENT_BIN is the static musl binary this daemon ships with.
        let inject = if ga.is_empty() {
            String::new()
        } else {
            format!("mkdir -p \"$w/root/usr/local/bin\"; install -m755 {ga} \"$w/root/usr/local/bin/guest-agent\";")
        };
        sh(&format!(
            r#"set -e
w="{w}"
for d in proc sys dev dev/pts tmp run; do mkdir -p "$w/root/$d"; done
{inject}
test -x "$w/root/usr/local/bin/guest-agent" || {{ echo "the image has no /usr/local/bin/guest-agent; set SBX_GUEST_AGENT_BIN" >&2; exit 1; }}
rm -f {rootfs}
mkfs.ext4 -F -q -d "$w/root" {rootfs} {size_mb}M"#,
            w = bd.display(),
            rootfs = rootfs.display()
        ))?;
        Ok(("image".to_string(), std::fs::metadata(&rootfs).map(|m| m.len()).unwrap_or(0)))
    })
    .await?
}

async fn image_bytes(name: &str) -> u64 {
    image_inspect(&podman_image(name)).await.and_then(|i| i["Size"].as_u64()).unwrap_or(0)
}

/// Deleting the record has to delete the image too, or a `vm`-tier host leaks a
/// container image per snapshot it ever had.
pub fn forget_podman_image(name: &str) {
    let image = podman_image(name);
    tokio::spawn(async move {
        if let Err(e) = image_remove(&image).await {
            tracing::debug!(%image, error = %e, "no snapshot image to remove");
        }
    });
}

/// A fresh `building` row.
pub fn new_info(name: &str, source: SnapshotSource, warm: u32, memory_snapshot: bool) -> SnapshotInfo {
    SnapshotInfo {
        name: name.to_string(),
        state: SnapshotState::Building,
        kind: if source.sandbox_id.is_some() { "vm".into() } else { "image".into() },
        source,
        created_at: now_rfc3339(),
        bytes: 0,
        error: None,
        host_id: None,
        warm,
        // The request's wish; `spawn_build` replaces it with what happened.
        memory_snapshot,
        warm_ready: 0,
        // The store stamps its own runtime on every row it hands back.
        runtime: String::new(),
        security: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_image_refs_are_checked_before_anything_is_built() {
        assert!(valid_name("node22") && valid_name("a.b-c_1"));
        assert!(!valid_name("Node22"), "uppercase is not a podman tag");
        assert!(!valid_name(""), "and neither is empty");
        assert!(!valid_name("-x"), "nor a leading dash");
        assert!(check_image_ref("node:22-bookworm").is_ok());
        assert!(check_image_ref("ghcr.io/o/r:1.2").is_ok());
        assert!(check_image_ref("alpine@sha256:abc").is_ok());
        assert!(check_image_ref("node").is_err(), "untagged is not a snapshot");
        assert!(check_image_ref("node:latest").is_err());
        // A registry port must not read as a tag.
        assert!(check_image_ref("reg:5000/img").is_err());
        assert!(check_image_ref("reg:5000/img:1").is_ok());
    }

    fn store(dir: &std::path::Path) -> Store {
        let mut cfg = crate::config::Config::resolve(crate::config::FileConfig::default());
        cfg.state_dir = dir.display().to_string();
        Store::load(&cfg, "vm")
    }

    #[tokio::test]
    async fn the_store_round_trips_and_a_name_is_claimed_once() {
        let dir = std::env::temp_dir().join(format!("sbx-snapstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = store(&dir);
        let info = new_info("t1", SnapshotSource { image: Some("node:22".into()), ..Default::default() }, 0, false);
        assert!(s.claim(&info).await);
        assert!(!s.claim(&info).await, "a taken name is a 409");
        let mut done = info.clone();
        done.state = SnapshotState::Active;
        s.update(done).await;

        // A second daemon start must see it, and see it as active.
        let s2 = store(&dir);
        assert_eq!(s2.get("t1").await.unwrap().state, SnapshotState::Active);
        assert!(s2.remove("t1").await);
        assert_eq!(s2.list().await.len(), 1, "only the synthetic base row is left");

        // A row still `building` on disk is an error after a restart, not a lie.
        let s3 = store(&dir);
        assert!(s3.claim(&info).await);
        let s4 = store(&dir);
        assert_eq!(s4.get("t1").await.unwrap().state, SnapshotState::Error);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// C3: a `DELETE` while the build runs is the cancel, and the build's final
    /// write must not bring the row back (which also blocked the name until a
    /// second `DELETE`).
    #[tokio::test]
    async fn a_template_deleted_while_building_does_not_come_back() {
        let dir = std::env::temp_dir().join(format!("sbx-snapcancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = store(&dir);
        let info = new_info("t1", SnapshotSource { image: Some("node:22".into()), ..Default::default() }, 0, false);
        assert!(s.claim(&info).await);
        assert!(s.still_claimed("t1").await, "the build owns the name while it works");

        assert!(s.remove("t1").await, "DELETE lands mid-build");
        // What `spawn_build` consults before writing its finished row: it writes
        // nothing, so the name is free and a restart sees no row at all.
        assert!(!s.still_claimed("t1").await);
        assert!(s.get("t1").await.is_none());
        assert!(store(&dir).get("t1").await.is_none(), "and nothing was left on disk");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// v4c §3a: every row this host serves carries this host's pooled runtime,
    /// `base` included — including a record written before the field existed.
    #[tokio::test]
    async fn every_row_carries_the_hosts_runtime() {
        let dir = std::env::temp_dir().join(format!("sbx-snaprt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = store(&dir);
        assert!(s.claim(&new_info("t1", SnapshotSource::default(), 0, false)).await);
        assert!(s.list().await.iter().all(|i| i.runtime == "vm"), "{:?}", s.list().await);
        assert_eq!(s.get(BASE).await.unwrap().runtime, "vm");
        assert_eq!(s.set_warm("t1", 2).await.unwrap().runtime, "vm");

        // A native-only host pools nothing, so its rows name no runtime.
        let mut cfg = crate::config::Config::resolve(crate::config::FileConfig::default());
        cfg.state_dir = dir.display().to_string();
        assert_eq!(Store::load(&cfg, "").get("t1").await.unwrap().runtime, "");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// §3a: `base` is always there, always active, and is not a real record.
    #[tokio::test]
    async fn base_is_a_synthetic_active_row_that_cannot_be_claimed() {
        let dir = std::env::temp_dir().join(format!("sbx-snapbase-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = store(&dir);
        let b = s.get(BASE).await.expect("base is always listed");
        assert_eq!((b.state, b.kind.as_str(), b.bytes), (SnapshotState::Active, "image", 0));
        assert!(b.source.image.is_some(), "it names the configured base image");
        assert_eq!(s.list().await.first().unwrap().name, BASE, "and it comes first");
        assert!(!s.claim(&new_info(BASE, SnapshotSource::default(), 0, false)).await, "the name is reserved");
        assert!(!s.remove(BASE).await, "and it is not removable");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
