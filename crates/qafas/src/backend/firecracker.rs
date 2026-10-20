//! Remote backend: one Firecracker microVM per sandbox, under the jailer
//! (PLAN §5). Linux + KVM only; it cannot run on the dev Mac, so it is compiled
//! for both musl targets and validated on the KVM box at Gate E.
//!
//! Layout per sandbox N (N = 1..=126, one /30 each):
//!   TAP  sbxtapN          172.16.N.1/30 host, 172.16.N.2/30 guest
//!   jail $SBX_FC_JAIL/firecracker/<id>/root
//!   API  <jail>/run/fc.sock          vsock <jail>/v.sock
//!
//! nftables lets the tap reach only the host proxy on 3128; everything else
//! from the sandbox subnets is dropped (D7).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyperlocal::UnixConnector;
use serde_json::{json, Value};

use proto::SandboxState;

use super::{Backend, BoxFut, Connector, Sandbox, Spec};
use crate::config::Config;
use crate::events::{now_ms, now_rfc3339};
use crate::livetable::{archive_dir, jail_dir, jail_id, jail_root, LiveRecord};

pub struct Firecracker {
    cfg: Arc<Config>,
    http: Client<UnixConnector, Full<Bytes>>,
    /// The /30 slots in use, 1..=126. The counter this replaced wrapped, so the
    /// 127th sandbox a daemon ever made got slot 1 back and `ensure_tap` deleted
    /// the live sandbox's tap to build it, putting two guests on one address.
    /// Only `destroy` gives a slot back.
    slots: Mutex<BTreeSet<u32>>,
    /// Turns true when the daemon starts shutting down (`begin_shutdown`).
    stopping: tokio::sync::watch::Sender<bool>,
}

/// How many /30s `ips` carves out of 172.16.0.0/16.
const SLOTS: u32 = 126;

/// The lowest free slot, marked taken. A free function so the accounting is
/// testable without a Firecracker host.
fn take_slot(slots: &mut BTreeSet<u32>) -> anyhow::Result<u32> {
    let slot = (1..=SLOTS)
        .find(|s| !slots.contains(s))
        .ok_or_else(|| anyhow::anyhow!("host has no free network slot ({SLOTS} microVMs)"))?;
    slots.insert(slot);
    Ok(slot)
}

fn sh(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(bin).args(args).output()?;
    if !out.status.success() {
        anyhow::bail!("{bin} {args:?}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// The jailer daemonises: the VM is `/firecracker --id <jail_id> ...` reparented
/// to init. `--` keeps pkill from reading `--id` as one of its own options
/// (which made every destroy a silent no-op).
fn kill_vm(jail_id: &str) -> anyhow::Result<()> {
    let pat = format!("^/firecracker --id {jail_id} ");
    sh("pkill", &["-KILL", "-f", "--", &pat])?;
    // pkill returns once the signal is sent, not once the process is gone; a
    // `start` right behind a `stop` must not race the old VM's teardown for the
    // same jail. Unmapping a 1 GiB guest takes tens of milliseconds.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && sh("pgrep", &["-f", "--", &pat]).is_ok() {
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// Is the VM whose pid is in `pid_file` still running? The pid alone would not
/// do: a recycled one reads as alive, so the process has to still *be* this VM,
/// which its own command line says. Answers `true` when it cannot tell — the
/// reaper destroys what this reports dead, and listing a dead sandbox for
/// another five seconds is the cheaper mistake.
fn pid_alive(pid_file: &std::path::Path, jail_id: &str) -> bool {
    let Some(pid) = std::fs::read_to_string(pid_file).ok().and_then(|s| s.trim().parse::<u32>().ok()) else {
        return true;
    };
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|argv| String::from_utf8_lossy(&argv).contains(jail_id))
        .unwrap_or(false)
}

impl Firecracker {
    /// `keep` is what `livetable::plan` re-adopts: sandboxes of the previous
    /// run that are `stopped` or `archived` and still have their files. Their
    /// jails, archives and /30 slots are the only things the startup sweep
    /// leaves alone.
    pub fn new(cfg: Arc<Config>, keep: &[LiveRecord]) -> anyhow::Result<Self> {
        for p in [&cfg.fc_bin, &cfg.fc_jailer, &cfg.fc_kernel, &cfg.fc_rootfs] {
            if !std::path::Path::new(p).exists() {
                anyhow::bail!("firecracker backend: {p} does not exist");
            }
        }
        // No idle pooling: the socket path is reused across a stop/start, and a
        // pooled connection to the previous (dead) firecracker fails the first
        // call on the new one with `SendRequest`.
        let http = Client::builder(hyper_util::rt::TokioExecutor::new()).pool_max_idle_per_host(0).build(UnixConnector);
        // `sweep_orphans` runs next and deletes every `sbxtap*` on the host and
        // every jail without an owner, so the re-adopted slots are the only ones
        // taken the moment it returns.
        let slots = keep.iter().filter_map(|r| slot_of(r.peer_ip).ok()).collect();
        let fc = Self { cfg, http, slots: Mutex::new(slots), stopping: tokio::sync::watch::channel(false).0 };
        fc.nftables()?;
        fc.sweep_orphans(keep);
        Ok(fc)
    }

    /// Kills every jailed VM a previous run left behind (a crash, or a stop
    /// that timed out before every VM was destroyed): each is a firecracker
    /// process, a tap and a jail directory holding huge pages nobody can use.
    fn sweep_orphans(&self, keep: &[LiveRecord]) {
        let kept: BTreeSet<String> = keep.iter().map(|r| jail_id(&r.id)).collect();
        let dir = PathBuf::from(&self.cfg.fc_jail_dir).join("firecracker");
        let mut n = 0;
        let mut killed = BTreeSet::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let jail_id = e.file_name().to_string_lossy().to_string();
                // Even a re-adopted sandbox is meant to have no process: whatever
                // still runs under its jail id is an orphan of the previous run.
                let _ = kill_vm(&jail_id);
                killed.insert(jail_id.clone());
                if kept.contains(&jail_id) {
                    continue;
                }
                let _ = std::fs::remove_dir_all(e.path());
                n += 1;
            }
        }
        let _ = sh("sh", &["-c", "for t in $(ip -o link | awk -F': ' '/sbxtap/{print $2}'); do ip link del $t; done"]);
        // The jailer makes `/sys/fs/cgroup/firecracker/<jail>` per VM and never
        // removes it; a live VM's dir is non-empty and `rmdir` leaves it alone.
        let left = sweep_cgroups(&host_cgroup_dir(""), &killed, SWEEP_CGROUP_WAIT);
        if left > 0 {
            tracing::warn!(cgroups = left, "microVM cgroups still busy after the sweep; the next start retries");
        }
        // A `stop` keeps the guest IP so the scoped token and the endpoint stay
        // valid, which means the tap has to come back before the sandbox can be
        // started. An archived sandbox has none by design; `start` builds it.
        for r in keep.iter().filter(|r| r.state == SandboxState::Stopped) {
            if let Ok(slot) = slot_of(r.peer_ip) {
                if let Err(e) = ensure_tap(slot) {
                    tracing::warn!(error = %e, sandbox_id = %r.id, slot, "re-adopted tap not re-created");
                }
            }
        }
        if n > 0 {
            tracing::warn!(vms = n, "killed microVMs left by a previous run");
        }
        // An archive directory with no record is a 2.4 GB leak nobody owns.
        let mut a = 0;
        if let Ok(entries) = std::fs::read_dir(&self.cfg.fc_archive_dir) {
            for e in entries.flatten() {
                if kept.contains(&e.file_name().to_string_lossy().to_string()) {
                    continue;
                }
                let _ = std::fs::remove_dir_all(e.path());
                a += 1;
            }
        }
        if a > 0 {
            tracing::warn!(archives = a, "removed archived microVMs left by a previous run");
        }
    }

    /// Whether the host can back one more guest with 2 MB pages right now.
    /// Falling back to 4 KB pages is slower, not broken; failing the boot is broken.
    fn hugepages_available(&self) -> bool {
        if !self.cfg.fc_hugepages {
            return false;
        }
        let free = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|m| {
                m.lines()
                    .find(|l| l.starts_with("HugePages_Free:"))
                    .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
            })
            .unwrap_or(0);
        let need = u64::from(self.cfg.fc_mem_mib) / 2;
        if free < need {
            tracing::warn!(free, need, "not enough free huge pages; booting this guest on 4 KB pages");
        }
        free >= need
    }

    /// One ruleset for all sandboxes: the only thing a tap may reach is the
    /// host-side egress proxy.
    fn nftables(&self) -> anyhow::Result<()> {
        let _ = sh("nft", &["add", "table", "inet", "sbx"]);
        let _ = sh("nft", &["add", "chain", "inet", "sbx", "input", "{ type filter hook input priority 0 ; }"]);
        let _ = sh("nft", &["add", "chain", "inet", "sbx", "forward", "{ type filter hook forward priority 0 ; }"]);
        sh("nft", &["flush", "chain", "inet", "sbx", "input"])?;
        sh("nft", &["flush", "chain", "inet", "sbx", "forward"])?;
        sh("nft", &["add", "rule", "inet", "sbx", "input", "iifname", "sbxtap*", "tcp", "dport", "3128", "accept"])?;
        sh("nft", &["add", "rule", "inet", "sbx", "input", "iifname", "sbxtap*", "drop"])?;
        // The proxy listens on every interface (a tap's address does not exist
        // until its sandbox does); only the taps may use it, or a neighbour host
        // would have an open proxy to the allowlist.
        sh(
            "nft",
            &["add", "rule", "inet", "sbx", "input", "iifname", "!=", "sbxtap*", "tcp", "dport", "3128", "drop"],
        )?;
        // No routing between sandboxes and no route to anywhere else.
        sh("nft", &["add", "rule", "inet", "sbx", "forward", "iifname", "sbxtap*", "drop"])?;
        sh("nft", &["add", "rule", "inet", "sbx", "forward", "oifname", "sbxtap*", "drop"])?;
        Ok(())
    }

    /// Reserves the lowest free /30 for a new sandbox.
    fn take_slot(&self) -> anyhow::Result<u32> {
        take_slot(&mut self.slots.lock().expect("slot set"))
    }

    /// Gives one back. Only `destroy` does: `stop` keeps the guest IP so the
    /// scoped token and the endpoint stay valid, and `archive` deletes the tap
    /// but not the reservation, because `start` from an archive reads the slot
    /// back out of `peer_ip` and re-creates exactly that tap.
    fn free_slot(&self, slot: u32) {
        self.slots.lock().expect("slot set").remove(&slot);
    }

    async fn api(&self, sock: &PathBuf, method: &str, path: &str, body: Value) -> anyhow::Result<()> {
        let _ = self.api_body(sock, method, path, body).await?;
        Ok(())
    }

    async fn api_body(&self, sock: &PathBuf, method: &str, path: &str, body: Value) -> anyhow::Result<Bytes> {
        let uri: hyper::Uri = hyperlocal::Uri::new(sock, path).into();
        let mut req = hyper::Request::builder().method(method).uri(uri).header("content-type", "application/json");
        if method == "GET" {
            req = req.header("accept", "application/json");
        }
        let payload = if method == "GET" { Vec::new() } else { serde_json::to_vec(&body)? };
        let resp = self.http.request(req.body(Full::new(Bytes::from(payload)))?).await?;
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await?.to_bytes();
        if !(200..300).contains(&status) {
            anyhow::bail!("firecracker {method} {path} -> {status}: {}", String::from_utf8_lossy(&bytes));
        }
        Ok(bytes)
    }
}

/// Ready is a connect that succeeds: firecracker's `bind` creates the socket file
/// before its `listen`, so the file existing says nothing about being served.
async fn wait_for(path: &PathBuf, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    anyhow::bail!("{} never accepted a connection", path.display())
}

/// `wait_healthy`, except that it gives up the moment `stop` turns true. Dropping
/// the wait is safe: it holds nothing, and the caller's error path does the
/// cleaning (`create` kills the VM and removes its jail, tap and cgroup).
async fn healthy_unless_shutdown(
    conn: &Connector,
    within: Duration,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tokio::select! {
        r = super::wait_healthy(conn, within) => r,
        _ = async {
            // A dropped sender is not a shutdown.
            if stop.wait_for(|s| *s).await.is_err() {
                std::future::pending::<()>().await;
            }
        } => anyhow::bail!("qafas is shutting down"),
    }
}

impl Backend for Firecracker {
    fn name(&self) -> &'static str {
        "firecracker"
    }
    fn pool_by_workspace(&self) -> bool {
        false
    }
    fn begin_shutdown(&self) {
        self.stopping.send_replace(true);
    }

    fn create(&self, spec: Spec) -> BoxFut<'_, anyhow::Result<Sandbox>> {
        Box::pin(async move {
            let id = spec.id.clone();
            // Nothing to boot for a daemon that is going down (a refill or a scan
            // that started just before SIGTERM).
            if *self.stopping.borrow() {
                anyhow::bail!("qafas is shutting down");
            }
            // Before anything is written or spawned: a host with no address left
            // says so, rather than booting a VM onto somebody else's subnet.
            let slot = self.take_slot()?;
            match self.boot(spec, slot).await {
                Ok(sb) => Ok(sb),
                Err(e) => {
                    // A half-booted VM is still a firecracker process holding memory,
                    // and its tap outlives it unless it goes here too (E1b). So does
                    // its cgroup: the jailer makes it before the VM exists, and it
                    // is awaited here (not spawned like `destroy`'s) because a
                    // create that fails at shutdown must finish this before the
                    // runtime goes, or the dir waits for the next start's sweep.
                    let _ = kill_vm(&jail_id(&id));
                    let _ = std::fs::remove_dir_all(jail_dir(&self.cfg, &id));
                    let _ = sh("ip", &["link", "del", &tap_name(slot)]);
                    self.free_slot(slot);
                    remove_dir_within(host_cgroup_dir(&jail_id(&id)), CGROUP_WAIT).await;
                    Err(e)
                }
            }
        })
    }

    /// v5 §3a. Guest RAM and vCPUs come out of the memory snapshot, so a
    /// restored VM cannot be resized from the host: the guest agent (root, PID
    /// 1) makes a cgroup v2 leaf inside instead, and the host writes a `cpu.max`
    /// backstop on the VM's own cgroup — the one the jailer's
    /// `--cgroup-version 2` gave it — so a guest that ignores its own quota
    /// still cannot take more than its share of host CPU.
    // design: guest RAM/vCPU are the snapshot's, so `mem_mib` above the template RAM is a 409 rather than a resize; a balloon device is the upgrade.
    fn apply_limits(&self, sb: &Sandbox, l: &proto::SandboxLimits) -> BoxFut<'_, anyhow::Result<()>> {
        let (conn, id, l) = (sb.connector.clone(), sb.id.clone(), *l);
        Box::pin(async move {
            super::set_limits(&conn, None, &l).await?;
            let quota = (l.cpus * 100_000.0).round() as i64;
            let path = host_cgroup_dir(&jail_id(&id)).join("cpu.max");
            if let Err(e) = std::fs::write(&path, format!("{quota} 100000")) {
                // Not fatal: the in-guest cgroup above is the enforcement the
                // contract promises, and this is the backstop for a guest that
                // has somehow dropped it.
                tracing::warn!(error = %e, path = %path.display(), "host cpu.max backstop not written");
            }
            Ok(())
        })
    }

    fn usage(&self, sb: &Sandbox) -> BoxFut<'_, Option<proto::SandboxUsage>> {
        let conn = sb.connector.clone();
        Box::pin(async move { super::guest_usage(&conn, None).await })
    }

    /// Two file reads per live sandbox per reaper tick, and no fork: the jailer
    /// writes firecracker's host pid into the jail before it execs, and
    /// `clean_for_restart` removes it, so the file is this incarnation's.
    fn alive(&self, sb: &Sandbox) -> BoxFut<'_, bool> {
        let (pid_file, jail_id) = (jail_root(&self.cfg, &sb.id).join("firecracker.pid"), jail_id(&sb.id));
        Box::pin(async move { pid_alive(&pid_file, &jail_id) })
    }

    /// A stopped or archived sandbox is a jail (or an archive) and an address;
    /// there is no process and no boot to redo, so the `Sandbox` is just the
    /// record read back. `start` does the rest.
    fn adopt(&self, rec: &LiveRecord) -> Option<Sandbox> {
        Some(Sandbox {
            id: rec.id.clone(),
            template: rec.template.clone(),
            workspace_path: rec.workspace_path.clone(),
            connector: Connector::Vsock {
                uds: jail_root(&self.cfg, &rec.id).join("v.sock"),
                port: proto::GUEST_AGENT_PORT as u32,
                keepalive: Default::default(),
            },
            agent_token: None,
            peer_ip: rec.peer_ip,
            created_at: rec.created_at.clone(),
            // It is not running, so it has no readiness and no boot to report.
            ready_at: None,
            boot_ms: 0,
        })
    }

    fn destroy(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let (id, peer) = (sb.id.clone(), sb.peer_ip);
        Box::pin(async move {
            // Killing the jailer takes the VM with it (--new-pid-ns).
            let _ = kill_vm(&jail_id(&id));
            remove_host_cgroup(&jail_id(&id));
            if let Ok(slot) = slot_of(peer) {
                let _ = sh("ip", &["link", "del", &tap_name(slot)]);
                // The address is free for the next sandbox only now.
                self.free_slot(slot);
            }
            let _ = std::fs::remove_dir_all(jail_dir(&self.cfg, &id));
            // A sandbox destroyed while archived still owns a full memory image.
            let _ = std::fs::remove_dir_all(archive_dir(&self.cfg, &id));
            Ok(())
        })
    }

    // ---------------------------------------------------------------- v3 lifecycle

    /// Every verb: only a microVM can snapshot RAM.
    fn supports_lifecycle(&self, _verb: super::Verb) -> bool {
        true
    }

    fn stop(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let id = sb.id.clone();
        Box::pin(async move {
            let root = jail_root(&self.cfg, &id);
            self.snapshot_into(&id, &root.join("snap")).await?;
            kill_vm(&jail_id(&id))?;
            // The tap and the jail stay: `start` restores into exactly this jail,
            // with the same guest IP, so the scoped token and endpoint keep working.
            Ok(())
        })
    }

    fn start(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let (id, peer) = (sb.id.clone(), sb.peer_ip);
        Box::pin(async move {
            let slot = slot_of(peer)?;
            let (host_ip, guest_ip) = ips(slot);
            ensure_tap(slot)?;
            let root = jail_root(&self.cfg, &id);

            // Archived: the snapshot and the two images it needs live outside the
            // jail, which was deleted. Move them back in (a hard link on the same
            // filesystem, a copy across one).
            let archive = archive_dir(&self.cfg, &id);
            if archive.join("vmstate").exists() {
                for (name, dst) in [
                    ("vmstate", root.join("snap/vmstate")),
                    ("mem", root.join("snap/mem")),
                    ("rootfs.ext4", root.join("rootfs.ext4")),
                    ("vmlinux", root.join("vmlinux")),
                ] {
                    link_or_copy(&archive.join(name).display().to_string(), &dst)?;
                }
                let _ = std::fs::remove_dir_all(&archive);
            }
            if !root.join("snap/vmstate").exists() {
                anyhow::bail!("no snapshot for {id}: nothing to start");
            }

            let api_sock = self.spawn_jailer(&id).await?;
            self.load_snapshot(&api_sock, &tap_name(slot)).await?;
            let connector = self.wait_agent(&root).await?;
            super::restored(
                &connector,
                None,
                &id,
                &format!("{guest_ip}/30"),
                &host_ip,
                &format!("http://{host_ip}:{}", proto::EGRESS_PROXY_PORT),
                now_ms(),
            )
            .await?;
            Ok(())
        })
    }

    fn pause(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let sock = jail_root(&self.cfg, &sb.id).join("run/fc.sock");
        Box::pin(async move { self.api(&sock, "PATCH", "/vm", json!({"state": "Paused"})).await })
    }

    fn resume(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let sock = jail_root(&self.cfg, &sb.id).join("run/fc.sock");
        Box::pin(async move { self.api(&sock, "PATCH", "/vm", json!({"state": "Resumed"})).await })
    }

    /// Called after `stop`: the VM is gone and `snap/` is in the jail.
    fn archive(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let (id, peer) = (sb.id.clone(), sb.peer_ip);
        Box::pin(async move {
            let (root, archive) = (jail_root(&self.cfg, &id), archive_dir(&self.cfg, &id));
            std::fs::create_dir_all(&archive)?;
            for (src, name) in [
                (root.join("snap/vmstate"), "vmstate"),
                (root.join("snap/mem"), "mem"),
                // Hard links, so keeping the images costs nothing but an inode:
                // a restore needs the exact rootfs the snapshot was taken on.
                (root.join("rootfs.ext4"), "rootfs.ext4"),
                (root.join("vmlinux"), "vmlinux"),
            ] {
                link_or_copy(&src.display().to_string(), &archive.join(name))?;
            }
            let _ = std::fs::remove_dir_all(jail_dir(&self.cfg, &id));
            // The tap goes, the slot stays reserved: `start` from the archive
            // derives the slot from `peer_ip` and re-creates this same tap.
            if let Ok(slot) = slot_of(peer) {
                let _ = sh("ip", &["link", "del", &tap_name(slot)]);
            }
            Ok(())
        })
    }

    /// `POST /snapshots {source:{sandbox_id}}`: a full snapshot of a *running*
    /// sandbox, which is left running.
    fn snapshot(&self, sb: &Sandbox, dir: PathBuf) -> BoxFut<'_, anyhow::Result<u64>> {
        let (id, sock) = (sb.id.clone(), jail_root(&self.cfg, &sb.id).join("run/fc.sock"));
        Box::pin(async move {
            let staging = jail_root(&self.cfg, &id).join("snap-new");
            let out = async {
                let r = self.snapshot_into(&id, &staging).await;
                // Whatever happened, the source sandbox goes back to running.
                let resumed = self.api(&sock, "PATCH", "/vm", json!({"state": "Resumed"})).await;
                r?;
                resumed?;
                std::fs::create_dir_all(&dir)?;
                let mut bytes = 0;
                for name in ["vmstate", "mem"] {
                    let dst = dir.join(name);
                    link_or_copy(&staging.join(name).display().to_string(), &dst)?;
                    bytes += std::fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
                }
                // The restore reopens the rootfs by name inside its own jail, so the
                // snapshot has to carry the exact image the source VM booted from.
                link_or_copy(
                    &jail_root(&self.cfg, &id).join("rootfs.ext4").display().to_string(),
                    &dir.join("rootfs.ext4"),
                )?;
                let _ = sh("chown", &["-R", "1000:1000", &dir.display().to_string()]);
                anyhow::Ok(bytes)
            }
            .await;
            // The staging is a full memory image (up to 1 GiB) inside the jail, and
            // a checkpoint that fails half way is exactly when it is biggest: it
            // does not outlive this call on any path (D5).
            let _ = std::fs::remove_dir_all(&staging);
            out
        })
    }
}

// ------------------------------------------------------------------ helpers

/// v5 §3a. Where the jailer parks one VM's host cgroup when it is given
/// `--cgroup-version 2`: `<v2 mount>/<exec file name>/<jail id>`.
fn host_cgroup_dir(jail_id: &str) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup/firecracker").join(jail_id)
}

/// How long a dead VM's cgroup may stay busy while the kernel tears the VM down.
const CGROUP_WAIT: Duration = Duration::from_secs(2);

/// All the orphans' cgroups together, at startup: they are retried side by side
/// under one deadline, so a host with twenty leftovers waits this long, not
/// twenty times `CGROUP_WAIT`.
const SWEEP_CGROUP_WAIT: Duration = Duration::from_secs(3);

/// `rmdir` of a dead VM's jailer cgroup, off the request path. `kill_vm` returns
/// when the process no longer matches `pgrep`, but the kernel is still tearing it
/// down (unmapping its guest memory, reaping it) and `rmdir` answers EBUSY until
/// the cgroup is empty, so a single attempt right after it leaves one empty dir
/// per destroy behind.
///
/// ponytail: ~2 s of polling every 50 ms, one fire-and-forget task per destroy;
/// a VM that takes longer leaves its (empty) cgroup for the next startup sweep,
/// which is also what a daemon that exits inside the window gets. Upgrade: wait
/// on the cgroup's `cgroup.events` (`populated 0`) instead of polling.
fn remove_host_cgroup(jail_id: &str) {
    tokio::spawn(remove_dir_within(host_cgroup_dir(jail_id), CGROUP_WAIT));
}

/// One `rmdir` pass: what is still there afterwards. A dir that was never there
/// is gone; one that refuses (EBUSY: the VM is still being reaped) stays listed.
fn rmdir_pass(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    dirs.into_iter()
        .filter(|d| match std::fs::remove_dir(d) {
            Ok(()) => false,
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        })
        .collect()
}

/// `rmdir` `dir`, again every 50 ms while it fails, until it is gone (a dir that
/// was never there counts) or `within` has passed. Whether it is gone.
async fn remove_dir_within(dir: PathBuf, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    let mut left = vec![dir];
    loop {
        left = rmdir_pass(left);
        if left.is_empty() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The startup sweep's cgroup pass over `root`: one `rmdir` of every entry (a
/// leftover from a destroy whose retry died with the daemon goes at once), then
/// the cgroups of the VMs this sweep just killed are retried together until
/// `within` runs out. Another host process's live VM is not waited for: only
/// `killed` names are. Blocking, like the `kill_vm` calls beside it. How many
/// are still there.
fn sweep_cgroups(root: &std::path::Path, killed: &BTreeSet<String>, within: Duration) -> usize {
    let all: Vec<PathBuf> = std::fs::read_dir(root).into_iter().flatten().flatten().map(|e| e.path()).collect();
    let mut busy: Vec<PathBuf> = rmdir_pass(all)
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| killed.contains(n.to_string_lossy().as_ref())))
        .collect();
    let deadline = Instant::now() + within;
    while !busy.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        busy = rmdir_pass(busy);
    }
    busy.len()
}

fn tap_name(slot: u32) -> String {
    format!("sbxtap{slot}")
}

/// One /30 per sandbox: `.1` is the host end, `.2` the guest.
fn ips(slot: u32) -> (String, String) {
    (format!("172.16.{slot}.1"), format!("172.16.{slot}.2"))
}

fn slot_of(peer: Option<IpAddr>) -> anyhow::Result<u32> {
    match peer {
        Some(IpAddr::V4(ip)) => Ok(u32::from(ip.octets()[2])),
        _ => anyhow::bail!("sandbox has no microVM address"),
    }
}

/// Idempotent: `archive` deletes the tap and `start` has to build one again.
fn ensure_tap(slot: u32) -> anyhow::Result<()> {
    let (tap, (host_ip, _)) = (tap_name(slot), ips(slot));
    let _ = sh("ip", &["link", "del", &tap]);
    sh("ip", &["tuntap", "add", &tap, "mode", "tap"])?;
    sh("ip", &["addr", "add", &format!("{host_ip}/30"), "dev", &tap])?;
    sh("ip", &["link", "set", &tap, "up"])?;
    Ok(())
}

/// Hard link where the filesystem allows it (a 1 GiB memory image is not worth
/// copying), `cp --reflink=auto` when it does not.
fn link_or_copy(src: &str, dst: &std::path::Path) -> anyhow::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(dst);
    if std::fs::hard_link(src, dst).is_ok() {
        return Ok(());
    }
    sh("cp", &["--reflink=auto", src, &dst.display().to_string()])
}

impl Firecracker {
    /// Pause and write a full snapshot into `dir` (which must be inside the
    /// jail: firecracker writes relative to its chroot). Leaves the VM paused.
    async fn snapshot_into(&self, id: &str, dir: &std::path::Path) -> anyhow::Result<()> {
        let root = jail_root(&self.cfg, id);
        let sock = root.join("run/fc.sock");
        // A huge-page guest cannot be restored through the file memory backend
        // (measured on firecracker 1.15: "Cannot restore hugetlbfs backed
        // snapshot by mapping the memory file. Please use uffd."). Fail here,
        // where the message can name the fix, rather than at restore time.
        let mc = self.api_body(&sock, "GET", "/machine-config", Value::Null).await?;
        let mc: Value = serde_json::from_slice(&mc).unwrap_or(Value::Null);
        if mc["huge_pages"].as_str().is_some_and(|h| h != "None") {
            anyhow::bail!(
                "this microVM is backed by {} huge pages, which the file memory backend cannot \
                 restore; run the host with SBX_FC_HUGEPAGES=0 (a UFFD handler is the upgrade)",
                mc["huge_pages"]
            );
        }
        std::fs::create_dir_all(dir)?;
        // `boot` hard-links the template's capture into `snap/`, and firecracker
        // writes in place: without this unlink a `stop` would overwrite the
        // template's memory image (shared by every sandbox restored from it).
        for f in ["vmstate", "mem"] {
            let _ = std::fs::remove_file(dir.join(f));
        }
        sh("chown", &["-R", "1000:1000", &dir.display().to_string()])?;
        let rel = dir.strip_prefix(&root).unwrap_or(dir).display().to_string();
        self.api(&sock, "PATCH", "/vm", json!({"state": "Paused"})).await?;
        self.api(
            &sock,
            "PUT",
            "/snapshot/create",
            json!({
                "snapshot_type": "Full",
                "snapshot_path": format!("{rel}/vmstate"),
                "mem_file_path": format!("{rel}/mem"),
            }),
        )
        .await
    }

    /// The jail keeps files a second jailer run refuses to recreate: the device
    /// nodes, the pid file, the API socket, the vsock UDS and the copied
    /// firecracker binary, which a VM still tearing down keeps busy (ETXTBSY on
    /// the jailer's write; unlinking is allowed). Measured on firecracker 1.15 —
    /// without this the jailer dies with `MknodDev EEXIST`.
    fn clean_for_restart(root: &std::path::Path) {
        let _ = std::fs::remove_dir_all(root.join("dev"));
        for f in ["firecracker.pid", "firecracker", "run/fc.sock"] {
            let _ = std::fs::remove_file(root.join(f));
        }
        if let Ok(rd) = std::fs::read_dir(root) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().starts_with("v.sock") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }

    /// Starts the jailer in `<jail_dir>/firecracker/<id>` and waits for the API
    /// socket. The jail may already exist (a restart after `stop`), which the
    /// jailer tolerates once `clean_for_restart` has run.
    async fn spawn_jailer(&self, id: &str) -> anyhow::Result<PathBuf> {
        let root = jail_root(&self.cfg, id);
        Self::clean_for_restart(&root);
        std::fs::create_dir_all(root.join("run"))?;
        // The jailer drops firecracker to 1000:1000; it must be able to open
        // the kernel, the rootfs and the memory image.
        sh("chown", &["-R", "1000:1000", &root.display().to_string()])?;

        let jail_id = jail_id(id);
        // The jailer/firecracker stderr goes to a log next to the jail so a boot
        // failure is diagnosable from the host without a console.
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.parent().unwrap_or(&root).join("jailer.log"))?;
        let log2 = log.try_clone()?;
        let jailer = Command::new(&self.cfg.fc_jailer)
            .stdin(std::process::Stdio::null())
            .stdout(log2) // the guest serial console
            .stderr(log)
            .args([
                "--id",
                &jail_id,
                "--exec-file",
                &self.cfg.fc_bin,
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--chroot-base-dir",
                &self.cfg.fc_jail_dir,
                "--new-pid-ns",
                // v5 §3a: one cgroup v2 directory per VM, so `apply_limits` has
                // somewhere on the host to write a `cpu.max` backstop. The
                // weight itself is the default; what matters is that the jailer
                // creates `<root>/firecracker/<jail id>` and moves the VM in.
                "--cgroup-version",
                "2",
                "--cgroup",
                "cpu.weight=100",
                "--",
                "--api-sock",
                "/run/fc.sock",
            ])
            .spawn()?;
        // The jailer exits as soon as firecracker is daemonised; reap it.
        std::thread::spawn(move || {
            let mut j = jailer;
            let _ = j.wait();
        });
        let api_sock = root.join("run/fc.sock");
        // 20 s: under load (rootfs builds, several restores) the jailer has been
        // seen to take more than 5 s to expose the socket; a wait costs nothing
        // when it is fast.
        wait_for(&api_sock, Duration::from_secs(20)).await?;
        Ok(api_sock)
    }

    /// Restore. The devices come out of the snapshot, so the only thing left to
    /// say is which tap this incarnation owns — the same one after `stop`, a
    /// fresh one when several sandboxes are restored from one snapshot.
    async fn load_snapshot(&self, api_sock: &PathBuf, tap: &str) -> anyhow::Result<()> {
        self.api(
            api_sock,
            "PUT",
            "/snapshot/load",
            json!({
                "snapshot_path": "snap/vmstate",
                "mem_backend": {"backend_type": "File", "backend_path": "snap/mem"},
                "resume_vm": true,
                "network_overrides": [{"iface_id": "eth0", "host_dev_name": tap}],
            }),
        )
        .await
    }

    async fn wait_agent(&self, root: &std::path::Path) -> anyhow::Result<Connector> {
        let vsock_uds = root.join("v.sock");
        wait_for(&vsock_uds, Duration::from_secs(5)).await?;
        let connector =
            Connector::Vsock { uds: vsock_uds, port: proto::GUEST_AGENT_PORT as u32, keepalive: Default::default() };
        // An idle cold boot answers in ~2.5 s; one boot costs ~1.7 cores (guest
        // init + bpftrace compile), so two or three at once on a 4-vCPU nested
        // host take 12–15 s. 15 s here failed the template capture on exactly
        // that host, and a missing template turns every create into a cold boot.
        // The guest also holds `/healthz` at 503 until its bpftrace feed is live
        // (15 s more nested; the guest gives up waiting after 60 s), so that no
        // sandbox is handed out, and no template captured, unwatched. A restore
        // of a template captured that way answers at once. 90 s still bounds a
        // guest that never comes up, and SIGTERM ends the wait at once: a cold
        // boot measured at 83 s would otherwise outlast systemd's 60 s stop
        // timeout and be SIGKILLed, orphaning the VM it was booting.
        healthy_unless_shutdown(&connector, Duration::from_secs(90), self.stopping.subscribe()).await?;
        Ok(connector)
    }

    /// `slot` is reserved by the caller, which is also what releases it when this
    /// fails: `boot` must not hand a half-set-up address back on its own.
    async fn boot(&self, spec: Spec, slot: u32) -> anyhow::Result<Sandbox> {
        let started = Instant::now();
        let created_at = now_rfc3339();
        let tap = tap_name(slot);
        let (host_ip, guest_ip) = ips(slot);
        ensure_tap(slot)?;

        // The jailer pivot_roots into <chroot>/firecracker/<id>/root, so the
        // kernel and rootfs have to be inside it. Both are read-only to the
        // guest (it overlays a tmpfs), so one image serves every VM: hard-link
        // it in and fall back to a copy only across filesystems.
        let root = jail_root(&self.cfg, &spec.id);
        std::fs::create_dir_all(root.join("run"))?;
        let snap = spec.snapshot.clone();
        // v4: a `vm` snapshot always restores, and so does an `image` template
        // whose memory was captured at build time (§3a "start is a restore").
        let restore = snap.as_ref().is_some_and(|s| s.is_restore());
        let rootfs = match &snap {
            Some(s) => s.dir.join("rootfs.ext4").display().to_string(),
            None => self.cfg.fc_rootfs.clone(),
        };
        link_or_copy(&self.cfg.fc_kernel, &root.join("vmlinux"))?;
        link_or_copy(&rootfs, &root.join("rootfs.ext4"))?;
        if let (true, Some(s)) = (restore, &snap) {
            for name in ["vmstate", "mem"] {
                link_or_copy(&s.dir.join(name).display().to_string(), &root.join("snap").join(name))?;
            }
        }

        let api_sock = self.spawn_jailer(&spec.id).await?;

        if restore {
            // Sub-100 ms: the memory image is mapped MAP_PRIVATE, so one
            // snapshot backs any number of sandboxes and each diverges on write.
            self.load_snapshot(&api_sock, &tap).await?;
        } else {
            // Huge pages: a guest page fault on fresh memory is a stage-2 fault on
            // the host, and 2 MB pages mean 512x fewer of them. On nested KVM that
            // is the difference between `node -e 0` in 3 s and in 100 ms — but a
            // huge-page guest cannot be snapshot-restored (see `snapshot_into`).
            // v5 §3a: a cold boot can be built to the requested size exactly.
            // A restore cannot — the vCPU count and the RAM come out of the
            // memory snapshot — which is why `apply_limits` writes an in-guest
            // cgroup instead and `mem_mib` above the template RAM is a 409.
            let mut mc = json!({
                "vcpu_count": (spec.limits.cpus.ceil() as u32).max(1),
                "mem_size_mib": u32::try_from(spec.limits.mem_mib).unwrap_or(self.cfg.fc_mem_mib),
                "smt": false,
            });
            if self.hugepages_available() {
                mc["huge_pages"] = json!("2M");
            }
            self.api(&api_sock, "PUT", "/machine-config", mc).await?;
            let boot_args = format!(
                // `quiet`: 200 printk lines over the emulated serial port cost ~1.7 s.
                "console=ttyS0 quiet loglevel=1 reboot=k panic=1 pci=off ro \
                 init=/usr/local/bin/guest-agent sbx.id={} sbx.workspace={} \
                 sbx.max_upload_mb={} sbx.disk_mb={} \
                 sbx.ip={guest_ip}/30 sbx.gw={host_ip} sbx.proxy=http://{host_ip}:{}",
                // Percent-encoded: the kernel splits the command line on
                // whitespace, and a workspace path may contain some.
                spec.id,
                agent_core::cmdline_encode(&spec.workspace_path),
                self.cfg.max_upload_mb,
                spec.limits.disk_mib,
                proto::EGRESS_PROXY_PORT
            );
            self.api(&api_sock, "PUT", "/boot-source", json!({"kernel_image_path": "vmlinux", "boot_args": boot_args}))
                .await?;
            self.api(
                &api_sock,
                "PUT",
                "/drives/rootfs",
                json!({"drive_id": "rootfs", "path_on_host": "rootfs.ext4",
                       "is_root_device": true, "is_read_only": true}),
            )
            .await?;
            self.api(&api_sock, "PUT", "/network-interfaces/eth0", json!({"iface_id": "eth0", "host_dev_name": tap}))
                .await?;
            // CID 3 is the first guest CID; the host side is a UDS the connector
            // dials with the `CONNECT <port>` handshake.
            self.api(&api_sock, "PUT", "/vsock", json!({"vsock_id": "vsock0", "guest_cid": 3, "uds_path": "/v.sock"}))
                .await?;
            self.api(&api_sock, "PUT", "/actions", json!({"action_type": "InstanceStart"})).await?;
        }

        let connector = self.wait_agent(&root).await?;
        if restore {
            // The clone is somebody else now: new id, new address, new canaries,
            // and a clock that stopped when the snapshot was taken.
            super::restored(
                &connector,
                None,
                &spec.id,
                &format!("{guest_ip}/30"),
                &host_ip,
                &format!("http://{host_ip}:{}", proto::EGRESS_PROXY_PORT),
                now_ms(),
            )
            .await?;
        }

        Ok(Sandbox {
            id: spec.id,
            template: spec.template,
            workspace_path: spec.workspace_path,
            connector,
            // vsock inside the jailer chroot: nothing but qafas can dial it.
            agent_token: None,
            peer_ip: guest_ip.parse::<IpAddr>().ok(),
            created_at,
            ready_at: Some(now_rfc3339()),
            boot_ms: started.elapsed().as_millis() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bound socket that is not yet listening (firecracker between `bind` and
    /// `listen`) is not ready; once it listens, it is. `path.exists()` fails this.
    #[tokio::test]
    async fn a_socket_is_ready_when_it_accepts_not_when_it_exists() {
        let path = std::env::temp_dir().join(format!("sbx-wf-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: plain libc calls on an fd and a sockaddr_un this test owns.
        let fd = unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as _;
            for (d, b) in addr.sun_path.iter_mut().zip(c.as_bytes()) {
                *d = *b as _;
            }
            assert_eq!(
                libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as _),
                0
            );
            fd
        };
        assert!(path.exists());
        assert!(wait_for(&path, Duration::from_millis(100)).await.is_err(), "bound, not listening");
        assert_eq!(unsafe { libc::listen(fd, 1) }, 0);
        wait_for(&path, Duration::from_millis(100)).await.unwrap();
        unsafe { libc::close(fd) };
        let _ = std::fs::remove_file(&path);
    }

    /// A guest agent that answers `/healthz` with `status` for as long as it lives.
    async fn fake_agent(status: &'static str) -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let _ = s.read(&mut [0u8; 512]).await;
                    let _ = s.write_all(format!("HTTP/1.0 {status}\r\ncontent-length: 0\r\n\r\n").as_bytes()).await;
                });
            }
        });
        addr
    }

    /// A create waiting on a guest that never reports healthy (a cold boot that
    /// has not got its bpftrace feed, 90 s) must stop waiting when SIGTERM
    /// arrives, not 90 s later: past systemd's 60 s the daemon is SIGKILLed and
    /// the VM it was booting is orphaned. Without the shutdown arm this waits out
    /// all 30 s.
    #[tokio::test]
    async fn a_create_waiting_for_its_guest_gives_up_when_shutdown_begins() {
        let agent = Connector::Tcp(fake_agent("503 Service Unavailable").await);
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tx.send_replace(true);
        });
        let t = Instant::now();
        let e = healthy_unless_shutdown(&agent, Duration::from_secs(30), rx).await.unwrap_err();
        assert!(e.to_string().contains("shutting down"), "{e}");
        assert!(t.elapsed() >= Duration::from_millis(100), "it waited until the signal, not before");
        assert!(t.elapsed() < Duration::from_secs(3), "and stopped with it, not at the 30 s bound: {:?}", t.elapsed());

        // Already shutting down when the wait starts: no wait at all.
        let (_tx, rx) = tokio::sync::watch::channel(true);
        let t = Instant::now();
        assert!(healthy_unless_shutdown(&agent, Duration::from_secs(30), rx).await.is_err());
        assert!(t.elapsed() < Duration::from_secs(1));

        // Without a shutdown it is still `wait_healthy`: a live guest is ready,
        // and a sender that went away is not a shutdown.
        let live = Connector::Tcp(fake_agent("200 OK").await);
        let (tx, rx) = tokio::sync::watch::channel(false);
        drop(tx);
        healthy_unless_shutdown(&live, Duration::from_secs(5), rx).await.unwrap();
    }

    /// The cgroup of a VM that is still tearing down refuses `rmdir`; here a file
    /// in a temp dir stands in for the processes that make it busy. The removal
    /// has to succeed once that clears, and give up (leaving the dir) at the deadline.
    #[tokio::test]
    async fn a_busy_cgroup_is_removed_once_it_empties_and_given_up_at_the_deadline() {
        let root = std::env::temp_dir().join(format!("sbx-cg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        // Busy for 150 ms, then empty: removed after that, well before the deadline.
        let (cg, member) = (root.join("sbx-busy"), root.join("sbx-busy/cgroup.procs"));
        std::fs::create_dir(&cg).unwrap();
        std::fs::write(&member, "1\n").unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            std::fs::remove_file(member).unwrap();
        });
        let t = Instant::now();
        assert!(remove_dir_within(cg.clone(), Duration::from_secs(5)).await);
        assert!(!cg.exists());
        assert!(t.elapsed() >= Duration::from_millis(150), "it cannot have succeeded while busy");
        assert!(t.elapsed() < Duration::from_secs(3), "and it stops as soon as it can");

        // Busy for good: gives up at the deadline, not before and not long after.
        let stuck = root.join("sbx-stuck");
        std::fs::create_dir(&stuck).unwrap();
        std::fs::write(stuck.join("cgroup.procs"), "1\n").unwrap();
        let t = Instant::now();
        assert!(!remove_dir_within(stuck.clone(), Duration::from_millis(200)).await);
        assert!(t.elapsed() >= Duration::from_millis(200) && t.elapsed() < Duration::from_secs(2));
        assert!(stuck.exists());

        // Never there (a VM that never got its cgroup): nothing to wait for.
        assert!(remove_dir_within(root.join("sbx-none"), Duration::from_secs(5)).await);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The startup sweep kills the previous run's VMs and then has to remove their
    /// cgroups, which stay busy while the kernel reaps each VM: one `rmdir` per
    /// orphan (what this replaced) left every one that had not finished behind.
    /// Here files in temp dirs stand in for the processes.
    #[test]
    fn the_sweep_waits_for_the_cgroups_of_the_vms_it_killed_and_only_those() {
        let root = std::env::temp_dir().join(format!("sbx-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let busy = |name: &str| {
            let cg = root.join(name);
            std::fs::create_dir(&cg).unwrap();
            std::fs::write(cg.join("cgroup.procs"), "1\n").unwrap();
            cg
        };
        // Empty already (a destroy whose retry died with the daemon): goes at once,
        // killed by this sweep or not.
        std::fs::create_dir(root.join("sbx-old")).unwrap();
        // Two orphans still being reaped; they empty after 200 ms.
        let (a, b) = (busy("sbx-a"), busy("sbx-b"));
        // Somebody else's live VM: never waited for, never removed.
        let foreign = busy("sbx-foreign");
        let reap = std::thread::spawn({
            let procs = [a.join("cgroup.procs"), b.join("cgroup.procs")];
            move || {
                std::thread::sleep(Duration::from_millis(200));
                for f in procs {
                    std::fs::remove_file(f).unwrap();
                }
            }
        });
        let killed: BTreeSet<String> = ["sbx-a", "sbx-b"].map(String::from).into();
        let t = Instant::now();
        assert_eq!(sweep_cgroups(&root, &killed, Duration::from_secs(5)), 0);
        assert!(t.elapsed() >= Duration::from_millis(150), "they were busy until then");
        assert!(t.elapsed() < Duration::from_secs(2), "and the wait ends when they are gone");
        reap.join().unwrap();
        assert!(!root.join("sbx-old").exists() && !a.exists() && !b.exists());
        assert!(foreign.exists(), "a cgroup with a live process is left alone");

        // Orphans that never empty: one shared deadline, not one each.
        let stuck: Vec<_> = (0..4).map(|i| busy(&format!("sbx-stuck{i}"))).collect();
        let killed: BTreeSet<String> = (0..4).map(|i| format!("sbx-stuck{i}")).collect();
        let t = Instant::now();
        assert_eq!(sweep_cgroups(&root, &killed, Duration::from_millis(300)), 4);
        assert!(t.elapsed() >= Duration::from_millis(300), "waited the whole bound");
        assert!(t.elapsed() < Duration::from_millis(900), "once for all four, not 4 x 300 ms: {:?}", t.elapsed());
        assert!(stuck.iter().all(|d| d.exists()));

        // A root that is not there (no firecracker cgroup yet): nothing to do.
        assert_eq!(sweep_cgroups(&root.join("nope"), &killed, Duration::from_secs(5)), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Liveness without forking `pgrep`. A pid that is not this jail's VM any
    /// more must read dead, a missing pid file must read alive (the reaper
    /// destroys what this calls dead), and a recycled pid must not fool it.
    #[test]
    fn liveness_comes_from_the_pid_file_and_the_command_line() {
        let dir = std::env::temp_dir().join(format!("sbx-pidfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("firecracker.pid");

        assert!(pid_alive(&f, "sbx-a"), "no pid file: cannot tell, so alive");
        std::fs::write(&f, "not-a-pid\n").unwrap();
        assert!(pid_alive(&f, "sbx-a"), "an unreadable pid file: same");

        // Our own pid, and a marker that really is on our command line.
        std::fs::write(&f, format!("{}\n", std::process::id())).unwrap();
        assert!(pid_alive(&f, "qafas"), "a live process whose argv matches is alive");
        assert!(!pid_alive(&f, "sbx-not-this-vm"), "the same pid under another jail id is not");

        std::fs::write(&f, "999999\n").unwrap();
        assert!(!pid_alive(&f, "sbx-a"), "a pid with no process is dead");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_sandbox_addresses_its_own_slot() {
        let ip: IpAddr = "172.16.7.2".parse().unwrap();
        assert_eq!(slot_of(Some(ip)).unwrap(), 7);
        assert_eq!(tap_name(7), "sbxtap7");
        assert_eq!(ips(7), ("172.16.7.1".to_string(), "172.16.7.2".to_string()));
        assert!(slot_of(None).is_err(), "a sandbox with no address cannot be restarted");
        assert_eq!(jail_id("sbx_a1"), "sbx-a1", "the jailer refuses underscores");
    }

    /// E1: the counter this replaced wrapped at 126 and handed the 127th create a
    /// live sandbox's address. A free list runs out instead.
    #[test]
    fn slots_are_the_lowest_free_one_and_run_out_at_126() {
        let mut s = BTreeSet::new();
        assert_eq!(take_slot(&mut s).unwrap(), 1);
        assert_eq!(take_slot(&mut s).unwrap(), 2);
        assert_eq!(take_slot(&mut s).unwrap(), 3);
        s.remove(&2); // a destroy
        assert_eq!(take_slot(&mut s).unwrap(), 2, "the freed slot is the lowest free one");

        // Fill the host: three are held, so 123 more. The 127th has nowhere to go
        // rather than stealing slot 1 from a running sandbox.
        for _ in 0..(SLOTS - 3) {
            take_slot(&mut s).unwrap();
        }
        assert_eq!(s.len(), SLOTS as usize);
        let e = take_slot(&mut s).unwrap_err().to_string();
        assert!(e.contains("no free network slot"), "{e}");
    }

    /// The four things a second jailer run in the same jail trips over.
    #[test]
    fn a_restart_clears_what_the_jailer_would_trip_over() {
        let root = std::env::temp_dir().join(format!("sbx-fc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("dev/net")).unwrap();
        std::fs::create_dir_all(root.join("run")).unwrap();
        std::fs::create_dir_all(root.join("snap")).unwrap();
        for f in ["firecracker.pid", "run/fc.sock", "v.sock", "v.sock_7777", "snap/mem"] {
            std::fs::write(root.join(f), b"x").unwrap();
        }
        Firecracker::clean_for_restart(&root);
        assert!(!root.join("dev").exists());
        assert!(!root.join("firecracker.pid").exists());
        assert!(!root.join("run/fc.sock").exists());
        assert!(!root.join("v.sock").exists() && !root.join("v.sock_7777").exists());
        assert!(root.join("snap/mem").exists(), "the snapshot is the whole point of the restart");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
