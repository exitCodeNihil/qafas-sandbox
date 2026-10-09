//! Every process a tool call spawns, with its argv, attributed to the tool call
//! that owns it.
//!
//! Attribution is by process group. `Spawner` puts each exec root in its own
//! group with `setpgid(0,0)`, so "the processes of this tool call" is exactly
//! "the processes whose pgid is the exec root's pid" — no ancestry walking, and
//! it survives double-forks that reparent onto init.
//!
//! Two feeds, per PLAN §2.5:
//!   * macOS — `kqueue`/`EVFILT_PROC` with `NOTE_FORK|NOTE_EXEC|NOTE_EXIT` on every
//!     process in the group; each fork event makes us enumerate and register the
//!     new children ourselves (`NOTE_TRACK` is EOPNOTSUPP on macOS 26), which
//!     the kernel extends to descendants, so a child that lives 3 ms is still
//!     seen; plus a 100 ms `proc_listpgrppids` sweep as belt and braces.
//!   * Linux — a 100 ms `/proc` sweep, and `bpftrace -f json` when the host has
//!     it and BTF (D19), which sees exec/exit without sampling.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proto::{EventType, Severity};
use serde::Serialize;
use serde_json::json;

use crate::rules::Rules;
use crate::{Corr, Emitter};

/// Sampling period for the sweep. Short enough that `npm ci`'s node children are
/// visible while they work, long enough to cost nothing.
/// macOS is kqueue-driven and only needs the sweep as a fallback; Linux has no
/// kernel feed inside a container (bpftrace covers the remote tier), so the
/// /proc walk is the feed and runs faster. ~50 µs per pass for a few processes.
#[cfg(target_os = "macos")]
const SWEEP: Duration = Duration::from_millis(100);
#[cfg(not(target_os = "macos"))]
const SWEEP: Duration = Duration::from_millis(25);
/// A forked child that has not exec'd yet is still the parent's image; the
/// sweep leaves it alone this long before reporting it as a fork-only process.
#[cfg(target_os = "macos")]
const FORK_GRACE: Duration = Duration::from_millis(500);

/// v5 §3a: the watchdog checks memory every sweep and the scratch directory
/// once a second, which is this many sweeps.
const DISK_EVERY: u64 = (1000 / SWEEP.as_millis()) as u64;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub exe: String,
    pub argv: Vec<String>,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_kb: Option<u64>,
    /// The exec whose process group this belongs to.
    pub root_pid: u32,
    /// The tool call that owns `root_pid`, so a caller with only a pid (the
    /// native tier's denial reports arrive in another process) can attribute it.
    #[serde(default)]
    pub pi_session: String,
    #[serde(default)]
    pub tool_call_id: String,
}

/// `http://host:port` (any of the four proxy variables) → `(host, port)`.
fn parse_proxy(url: &str) -> Option<(String, u16)> {
    let hp = url.trim().trim_start_matches("http://").trim_start_matches("https://").trim_end_matches('/');
    let (h, p) = hp.rsplit_once(':')?;
    Some((h.trim_matches(['[', ']']).to_string(), p.parse().ok()?))
}

/// The egress proxy the guest is *supposed* to talk to. Read per connect, not
/// once: a restored snapshot is handed a new proxy address (`/restored`) long
/// after the probe started, and a stale address turns every proxied request into
/// a `sandbox.denied` alert.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn proxy_dst() -> Option<(String, u16)> {
    ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]
        .iter()
        .find_map(|k| std::env::var(k).ok())
        .and_then(|u| parse_proxy(&u))
}

/// Destinations a sandboxed process may open directly: the egress proxy and
/// loopback. Everything else bypasses the proxy (§1.1 `sandbox.denied`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn dst_allowed(proxy: Option<&(String, u16)>, ip: &str, port: u16) -> bool {
    ip.starts_with("127.") || ip == "::1" || proxy.is_some_and(|(h, p)| h == ip && *p == port)
}

/// A wait(2) status — `task_struct.exit_code` has the same layout — split into
/// the protocol's `exit` and optional `signal` (§1 `process.exit`).
fn decode_status(status: i32) -> (Option<i32>, Option<String>) {
    match status & 0x7f {
        0 => (Some((status >> 8) & 0xff), None),
        sig => (
            Some(-1),
            nix::sys::signal::Signal::try_from(sig).ok().map(|s| s.as_str().trim_start_matches("SIG").to_string()),
        ),
    }
}

/// Called with each new exec's process group id. qafas's native tier uses it
/// to record the group on disk before anything runs, so a daemon that dies
/// without cleaning up can still kill the leftovers on its next start.
pub type WatchHook = Arc<dyn Fn(u32) + Send + Sync>;

/// v5 §3a. The dimensions the daemon-side watchdog holds where no kernel does
/// (macOS native). Zero means "somebody else is holding this one".
#[derive(Clone, Default)]
struct Budget {
    mem_bytes: u64,
    disk_bytes: u64,
    pids: u32,
    scratch: String,
}

#[derive(Default)]
struct Inner {
    /// pgid (== exec root pid) → the tool call that owns it.
    watched: Mutex<HashMap<u32, Corr>>,
    /// pid → what we last knew about it, plus when we first saw it.
    seen: Mutex<HashMap<u32, (ProcInfo, std::time::Instant)>>,
    hook: Mutex<Option<WatchHook>>,
    stop: AtomicBool,
    /// v5 §3a. What `PUT /limits` asked the watchdog to hold; a zero dimension
    /// means "nothing to enforce here", which is every tier with a cgroup.
    budget: Mutex<Option<Budget>>,
    /// Sweeps since the scratch directory was last measured — it is the only
    /// part of the watchdog that costs anything, so it runs once a second.
    disk_countdown: AtomicU64,
    /// v5 §3a. Process groups the watchdog has already killed, so one kill
    /// raises one alert however many sweeps see the aftermath. Cleared per pgid
    /// by `unwatch`, so a recycled pid is never mistaken for an old kill.
    killed: Mutex<HashSet<u32>>,
    /// v5.1. Execs the bpftrace feed could not attribute (`Monitor::unattributed_execs`).
    unattributed: AtomicU64,
    /// v5.1. Set once bpftrace attaches (remote tier): it then owns start/exit
    /// off the fork/exec/exit tracepoints, so the sweep must not also announce
    /// — it would catch a freshly forked child before its `exec` and race the
    /// tracepoint into a duplicate `process.start`. The sweep stays on for RSS
    /// and the watchdog only. On the vm tier bpftrace is absent and the sweep is
    /// the lifecycle feed as before.
    bpftrace_lifecycle: AtomicBool,
    /// pid → when we saw its fork; cleared on exec or exit (macOS).
    #[cfg(target_os = "macos")]
    forked: Mutex<HashMap<u32, std::time::Instant>>,
}

#[derive(Clone)]
pub struct Monitor {
    inner: Arc<Inner>,
    ev: Emitter,
    rules: Rules,
    #[cfg(target_os = "macos")]
    kq: Arc<sys::Kqueue>,
}

impl Monitor {
    pub fn new(ev: Emitter, rules: Rules) -> Self {
        let m = Self {
            inner: Arc::new(Inner::default()),
            ev,
            rules,
            #[cfg(target_os = "macos")]
            kq: Arc::new(sys::Kqueue::open()),
        };
        let bg = m.clone();
        std::thread::Builder::new().name("procmon".into()).spawn(move || bg.run()).expect("procmon thread");
        // The lifecycle flag is not set here: bpftrace takes seconds to compile
        // its program, and until its BEGIN probe reports in, the sweep is the
        // only feed there is (see the reader thread).
        #[cfg(target_os = "linux")]
        if !sys::spawn_bpftrace(m.clone()) {
            sys::spawn_canary_watch(m.clone());
        }
        m
    }

    /// The tool call a sandbox-wide signal belongs to: whichever exec is live.
    /// `None` when the sandbox is idle, which for the usage push also means
    /// "nothing worth sampling". With overlapping execs it picks one of them —
    /// which is why the canary watch prefers fanotify, whose events carry the
    /// pid, and only falls back to this with inotify.
    pub fn live_corr(&self) -> Option<Corr> {
        self.inner.watched.lock().unwrap().values().next().cloned()
    }

    /// Runs on every `watch`, before the process does anything.
    pub fn on_watch(&self, f: WatchHook) {
        *self.inner.hook.lock().unwrap() = Some(f);
    }

    /// A new exec root. `pid` is also its pgid.
    pub fn watch(&self, pid: u32, corr: Corr) {
        self.inner.watched.lock().unwrap().insert(pid, corr);
        let hook = self.inner.hook.lock().unwrap().clone();
        if let Some(f) = hook {
            f(pid);
        }
        #[cfg(target_os = "macos")]
        {
            self.kq.track(pid);
        }
    }

    /// The exec finished. Its children are swept once more so their exits are
    /// reported before we forget the group.
    pub fn unwatch(&self, pid: u32) {
        self.sweep();
        self.inner.watched.lock().unwrap().remove(&pid);
        self.inner.killed.lock().unwrap().remove(&pid);
        let mut seen = self.inner.seen.lock().unwrap();
        let gone: Vec<u32> = seen.iter().filter(|(_, (p, _))| p.root_pid == pid).map(|(k, _)| *k).collect();
        for pid in gone {
            seen.remove(&pid);
        }
    }

    /// `GET /processes` — everything alive right now, oldest first.
    pub fn snapshot(&self) -> Vec<ProcInfo> {
        let mut v: Vec<ProcInfo> = self.inner.seen.lock().unwrap().values().map(|(p, _)| p.clone()).collect();
        for p in v.iter_mut() {
            let c = self.corr_of(p.root_pid);
            p.pi_session = c.pi_session.clone();
            p.tool_call_id = c.tool_call_id.clone();
        }
        v.sort_by(|a, b| (a.started_at.clone(), a.pid).cmp(&(b.started_at.clone(), b.pid)));
        v
    }

    pub fn shutdown(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
    }

    /// The tool call that owns a pid, for signals that arrive with a pid and
    /// nothing else — a Seatbelt denial report, a bpftrace line. Falls back to
    /// the live pgid when the sweep has not seen the process yet.
    pub fn corr_for_pid(&self, pid: u32) -> Corr {
        let known = self.inner.seen.lock().unwrap().get(&pid).map(|(p, _)| p.root_pid);
        match known.or_else(|| sys::pgid_of(pid)) {
            Some(root) => self.corr_of(root),
            None => Corr::default(),
        }
    }

    fn corr_of(&self, root_pid: u32) -> Corr {
        self.inner.watched.lock().unwrap().get(&root_pid).cloned().unwrap_or_default()
    }

    /// Records a process we had not seen and emits `process.start` plus whatever
    /// rules its exe and argv trip.
    fn note_start(&self, p: ProcInfo) {
        {
            let mut seen = self.inner.seen.lock().unwrap();
            if seen.contains_key(&p.pid) {
                return;
            }
            seen.insert(p.pid, (p.clone(), std::time::Instant::now()));
        }
        let corr = self.corr_of(p.root_pid);
        self.ev.emit(
            &corr,
            EventType::ProcessStart,
            json!({"pid": p.pid, "ppid": p.ppid, "uid": p.uid, "exe": p.exe,
                   "argv": p.argv, "cwd": "", "root_pid": p.root_pid}),
        );
        if let Some(h) = Rules::scan_exe(&p.exe) {
            self.ev.alert(
                &corr,
                h.severity,
                h.rule,
                format!("{} executed {}", p.pid, h.path),
                json!({"pid": p.pid, "path": h.path, "evidence": {"argv": p.argv}}),
            );
        }
        // The exec root's command line was already scanned before it ran
        // (`exec::pre_flight`); repeating it here would double every alert.
        if p.pid == p.root_pid {
            return;
        }
        for h in self.rules.scan(&p.argv.join(" ")) {
            self.ev.alert(
                &corr,
                h.severity,
                h.rule,
                format!("{} referenced {}", p.exe, h.path),
                json!({"pid": p.pid, "path": h.path, "evidence": {"argv": p.argv}}),
            );
        }
    }

    /// `exit`/`signal` are `None` only when the platform never reported them
    /// (the /proc sweep sees a process that is already gone).
    pub fn note_exit(&self, pid: u32, exit: Option<i32>, signal: Option<String>) {
        let Some((p, since)) = self.inner.seen.lock().unwrap().remove(&pid) else { return };
        let mut data = json!({"pid": pid, "exit": exit, "duration_ms": since.elapsed().as_millis() as u64,
                   "rss_max_kb": p.rss_kb});
        if let Some(s) = signal {
            data["signal"] = json!(s);
        }
        self.ev.emit(&self.corr_of(p.root_pid), EventType::ProcessExit, data);
    }

    /// v5 §3a. The daemon-enforced budget (macOS native): what the watchdog in
    /// `sweep` compares against. Set by `PUT /limits`, replaced on every call.
    pub fn set_budget(&self, mem_bytes: u64, disk_bytes: u64, pids: u32, scratch: String) {
        *self.inner.budget.lock().unwrap() = Some(Budget { mem_bytes, disk_bytes, pids, scratch });
    }

    /// v5 §3a. `(rss bytes, cpu millis, process count)` summed over everything
    /// this sandbox is running — what `GET /usage` answers with where there is
    /// no cgroup to read.
    pub fn totals(&self) -> (u64, u64, u32) {
        let seen = self.inner.seen.lock().unwrap();
        let rss = seen.values().map(|(p, _)| p.rss_kb.unwrap_or(0) * 1024).sum();
        let cpu = seen.keys().filter_map(|p| sys::cpu_millis(*p)).sum();
        (rss, cpu, seen.len() as u32)
    }

    /// The watchdog of protocol §3a's `native` macOS row. Memory every sweep,
    /// scratch once a second; over either one the whole process group dies and
    /// the alert says which. Armed only for the dimensions nothing else holds
    /// (`limits::apply` decides which), because two enforcers racing produce two
    /// different stories about the same kill.
    fn watchdog(&self, rss_bytes: u64, group_sizes: &HashMap<u32, usize>) {
        let Some(b) = self.inner.budget.lock().unwrap().clone() else { return };
        let (mem, disk, scratch) = (b.mem_bytes, b.disk_bytes, b.scratch);
        // One alert per kill: a group we have already killed stays killed, and
        // the sweep keeps running. Without this the disk check re-fires every
        // second forever — killing the group does not delete the file that went
        // over — and a slow kill re-fires every sweep until the pids disappear.
        let fresh: Vec<u32> = {
            let killed = self.inner.killed.lock().unwrap();
            self.inner.watched.lock().unwrap().keys().copied().filter(|p| !killed.contains(p)).collect()
        };
        if fresh.is_empty() {
            return;
        }
        // Every group this sandbox is running, counted fresh each sweep — an
        // `RLIMIT_NPROC` sized once per spawn cannot see a group that grows
        // later, and on macOS that rlimit is per-uid anyway (`Limits::headroom`).
        let procs: usize = fresh.iter().filter_map(|p| group_sizes.get(p)).sum();
        let over = if mem > 0 && rss_bytes > mem {
            Some(format!("memory limit {} MiB hit (watchdog)", mem / (1024 * 1024)))
        } else if b.pids > 0 && procs > b.pids as usize {
            Some(format!("process limit {} hit (watchdog)", b.pids))
        } else if disk > 0
            && self.inner.disk_countdown.fetch_add(1, Ordering::Relaxed) % DISK_EVERY == 0
            && crate::limits::scratch_bytes(&scratch) > disk
        {
            Some(format!("disk limit {} MiB hit (watchdog)", disk / (1024 * 1024)))
        } else {
            None
        };
        let Some(msg) = over else { return };
        for root in &fresh {
            let _ =
                nix::sys::signal::killpg(nix::unistd::Pid::from_raw(*root as i32), nix::sys::signal::Signal::SIGKILL);
        }
        self.inner.killed.lock().unwrap().extend(fresh.iter().copied());
        // The tool call that owns the group we just killed, not whichever one
        // `watched` happens to list first.
        self.ev.alert(
            &self.corr_of(fresh[0]),
            Severity::Low,
            proto::rules::RESOURCE_LIMIT,
            msg,
            json!({"evidence": {"rss_bytes": rss_bytes, "pids": procs, "pgids": fresh}}),
        );
    }

    /// One pass over every watched process group.
    fn sweep(&self) {
        let roots: Vec<u32> = self.inner.watched.lock().unwrap().keys().copied().collect();
        // One kernel scan per tick for all of them, not one per group.
        let groups = sys::group_pids_all(&roots);
        // Where a cgroup answers `GET /usage` and holds the memory limit (every
        // Linux tier), nobody reads these per-pid numbers, so nobody pays for
        // them. Where there is none they are the only source there is, and a
        // reading from minutes ago would be worse than none.
        let refresh_rss = crate::limits::accounting_dir().is_none();
        // When bpftrace owns the lifecycle, the sweep observes but never announces.
        let lifecycle = !self.inner.bpftrace_lifecycle.load(Ordering::SeqCst);
        let mut alive: Vec<u32> = Vec::new();
        let mut sizes: HashMap<u32, usize> = HashMap::new();
        for (root, pids) in &groups {
            sizes.insert(*root, pids.len());
            for pid in pids {
                let pid = *pid;
                alive.push(pid);
                if let Some((p, _)) = self.inner.seen.lock().unwrap().get_mut(&pid) {
                    if refresh_rss {
                        p.rss_kb = sys::rss_kb(pid).or(p.rss_kb);
                    }
                    continue;
                }
                #[cfg(target_os = "macos")]
                if self.inner.forked.lock().unwrap().get(&pid).is_some_and(|t| t.elapsed() < FORK_GRACE) {
                    continue; // not exec'd yet; the kqueue exec event will announce it
                }
                if lifecycle {
                    if let Some(p) = sys::describe(pid, *root) {
                        self.note_start(p);
                    }
                }
            }
        }
        // Exits stay on in both modes: `note_exit` on a pid bpftrace already
        // reported is a no-op, and when the tracepoint drops one (perf-buffer
        // pressure, a SIGKILLed group) this is what still drains the group so
        // the exec can end. Only the *announce* races bpftrace; the exit does not.
        let dead: Vec<u32> = self.inner.seen.lock().unwrap().keys().filter(|p| !alive.contains(p)).copied().collect();
        for pid in dead {
            // The sweep only ever notices a process that is already reaped, so
            // there is no status left to report. Every kernel feed below has one.
            self.note_exit(pid, None, None);
        }
        self.watchdog(self.totals().0, &sizes);
    }

    fn run(self) {
        while !self.inner.stop.load(Ordering::SeqCst) {
            #[cfg(target_os = "macos")]
            {
                // Blocks up to SWEEP; every event it returns is a process the
                // sweep would otherwise have missed.
                for e in self.kq.wait(SWEEP) {
                    match e {
                        // A fork: the new child is somewhere in the parent's
                        // group. Register it now so its exec and exit reach us
                        // even if it is gone before the next sweep.
                        sys::ProcEvent::Fork(parent) => {
                            if let Some(root) = self.root_of(parent) {
                                let mut forked = self.inner.forked.lock().unwrap();
                                let seen = self.inner.seen.lock().unwrap();
                                for pid in sys::group_pids(root) {
                                    if !seen.contains_key(&pid) && self.kq.track(pid) {
                                        forked.insert(pid, std::time::Instant::now());
                                    }
                                }
                            }
                        }
                        // The real program is known only now: describe it fresh
                        // and (re)announce it, replacing any pre-exec record.
                        sys::ProcEvent::Exec(pid) => {
                            self.inner.forked.lock().unwrap().remove(&pid);
                            if let Some(root) = self.root_of(pid) {
                                if let Some(p) = sys::describe(pid, root) {
                                    // A script's interpreter exec (shebang) fires a
                                    // second NOTE_EXEC for the same image: not a new process.
                                    let same = self
                                        .inner
                                        .seen
                                        .lock()
                                        .unwrap()
                                        .get(&pid)
                                        .is_some_and(|(q, _)| q.exe == p.exe && q.argv == p.argv);
                                    if !same {
                                        self.inner.seen.lock().unwrap().remove(&pid);
                                        self.note_start(p);
                                    }
                                }
                            }
                        }
                        // NOTE_EXITSTATUS gives the wait status with the event.
                        sys::ProcEvent::Exit(pid, status) => {
                            self.inner.forked.lock().unwrap().remove(&pid);
                            let (exit, sig) = match status {
                                Some(s) => decode_status(s),
                                None => (None, None),
                            };
                            self.note_exit(pid, exit, sig)
                        }
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            std::thread::sleep(SWEEP);
            self.sweep();
        }
    }

    /// Which watched exec a pid belongs to, if any.
    ///
    /// By session first: every exec root calls `setsid` (`spawn::own_process_group`),
    /// so a session id *is* an exec root pid, and unlike the process group it
    /// survives a child that calls `setpgid` for its own job control. The group
    /// is the fallback for anything started before that was true.
    fn root_of(&self, pid: u32) -> Option<u32> {
        let watched = self.inner.watched.lock().unwrap();
        let known = |id: Option<u32>| id.filter(|i| watched.contains_key(i));
        known(sid_of(pid)).or_else(|| known(sys::pgid_of(pid)))
    }

    /// v5.1. Execs the bpftrace feed could not attribute to any watched exec —
    /// the process was gone before `/proc` could be asked and no fork event had
    /// named its parent. They are not dropped silently: the sweep still reports
    /// the ones that live long enough, and this says how often it is the only
    /// thing that did.
    pub fn unattributed_execs(&self) -> u64 {
        self.inner.unattributed.load(Ordering::Relaxed)
    }
}

/// The session a pid belongs to, or `None` when it is gone. Portable: `getsid`
/// is POSIX, so this needs no `/proc` on either platform.
pub fn sid_of(pid: u32) -> Option<u32> {
    let sid = unsafe { libc::getsid(pid as libc::pid_t) };
    (sid >= 0).then_some(sid as u32)
}

// ------------------------------------------------------------- bpftrace feed

impl Monitor {
    /// A `sched_process_exec`: the real program is known only now. `/proc` is
    /// the good description and `exe_hint` (bpftrace's `args->filename`) the
    /// fallback for a process that is already gone.
    ///
    /// At most one `process.start` per image per pid. A script's interpreter
    /// exec (shebang) fires a second event for the same image, and announcing a
    /// pid twice with no exit in between reads as two processes in the timeline.
    fn note_exec(&self, pid: u32, root: u32, exe_hint: &str) {
        let p = sys::describe(pid, root).unwrap_or_else(|| ProcInfo {
            pid,
            ppid: 0,
            uid: 0,
            exe: exe_hint.to_string(),
            argv: vec![exe_hint.to_string()],
            started_at: crate::now_rfc3339(),
            rss_kb: None,
            root_pid: root,
            pi_session: String::new(),
            tool_call_id: String::new(),
        });
        {
            let mut seen = self.inner.seen.lock().unwrap();
            if let Some((old, _)) = seen.get_mut(&pid) {
                if old.exe == p.exe {
                    // Same image. Take the better description if this event has
                    // one — a record whose argv is just its exe is what a
                    // process that outran `/proc` leaves behind — and say
                    // nothing, because nothing new started.
                    if old.argv.len() == 1 && old.argv[0] == old.exe && p.argv.len() > 1 {
                        *old = p;
                    }
                    return;
                }
            }
            seen.remove(&pid);
        }
        self.note_start(p);
    }

    /// An exec belonging to no exec root we can name. Never a silent drop: the
    /// `/proc` sweep still reports it if it lives to the next tick, and this
    /// counts how often that was the only feed that saw it.
    fn note_unattributed(&self, pid: u32) {
        let n = self.inner.unattributed.fetch_add(1, Ordering::Relaxed) + 1;
        // Loud once, then rarely: a feed that cannot attribute anything must not
        // also fill the guest log.
        if n == 1 || n % 100 == 0 {
            tracing::warn!(
                pid,
                total = n,
                "bpftrace exec with no resolvable exec root; only the /proc sweep will see it"
            );
        }
    }
}

/// The bpftrace feed's per-line state (D19).
///
/// Out here, and platform independent, because the feed is the one telemetry
/// path with no sampling — anything it drops is a process nobody ever hears
/// about — and a Linux-only closure inside a thread is code no test ever runs.
#[derive(Default)]
pub struct Lineage {
    /// pid → exec root, built from fork events so nothing depends on `/proc`
    /// still knowing a process that lived for a millisecond.
    of: HashMap<u32, u32>,
}

impl Lineage {
    /// One line of the feed. Handles the lifecycle half (fork/exec/exit) and
    /// returns the exec root for anything else, so the caller can attribute a
    /// syscall event to it.
    pub fn on_event(&mut self, mon: &Monitor, t: &str, pid: u32, v: &serde_json::Value) -> Option<u32> {
        if t == "fork" {
            let ppid = v["ppid"].as_u64().unwrap_or(0) as u32;
            let root = match mon.inner.watched.lock().unwrap().contains_key(&ppid) {
                true => Some(ppid),
                false => self.of.get(&ppid).copied(),
            };
            if let Some(r) = root {
                self.of.insert(pid, r);
            }
            return None;
        }
        if t == "exit" {
            self.of.remove(&pid);
            // `task_struct.exit_code` is wait(2)-shaped.
            let (exit, sig) = match v["st"].as_i64() {
                Some(st) => decode_status(st as i32),
                None => (None, None),
            };
            mon.note_exit(pid, exit, sig);
            return None;
        }
        // A fork event is the only record that outlives a process `/proc` never
        // saw; the kernel lookups are the fallback, in that order.
        let root = self.of.get(&pid).copied().or_else(|| mon.root_of(pid));
        match (t, root) {
            ("exec", Some(root)) => {
                mon.note_exec(pid, root, v["f"].as_str().unwrap_or("?"));
                None
            }
            (_, None) => {
                mon.note_unattributed(pid);
                None
            }
            (_, root) => root,
        }
    }
}

// ------------------------------------------------------------------ macOS

#[cfg(target_os = "macos")]
mod sys {
    use super::ProcInfo;
    use std::sync::Mutex;
    use std::time::Duration;

    // libproc, in libSystem. Not in the `libc` crate, so declared here.
    extern "C" {
        fn proc_listpgrppids(pgrpid: libc::pid_t, buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
    }

    /// Every pid in a process group. Empty when the group is gone.
    ///
    /// `proc_listpgrppids` returns the *count* of pids it wrote, not a byte
    /// count — the opposite of `proc_listpids` in the same header. Verified
    /// against a C probe on macOS 26; the test below pins it.
    pub fn group_pids(pgid: u32) -> Vec<u32> {
        let mut buf = vec![0i32; 1024];
        let n = unsafe {
            proc_listpgrppids(
                pgid as libc::pid_t,
                buf.as_mut_ptr() as *mut libc::c_void,
                (buf.len() * std::mem::size_of::<i32>()) as libc::c_int,
            )
        };
        if n <= 0 {
            return Vec::new();
        }
        buf.truncate((n as usize).min(buf.len()));
        buf.into_iter().filter(|p| *p > 0).map(|p| p as u32).collect()
    }

    /// Several groups at once. `proc_listpgrppids` already filters in the
    /// kernel, so one call per group is the cheap way round here.
    pub fn group_pids_all(pgids: &[u32]) -> std::collections::HashMap<u32, Vec<u32>> {
        pgids.iter().map(|g| (*g, group_pids(*g))).collect()
    }

    fn bsdinfo(pid: u32) -> Option<libc::proc_bsdinfo> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then_some(info)
    }

    pub fn pgid_of(pid: u32) -> Option<u32> {
        bsdinfo(pid).map(|i| i.pbi_pgid)
    }

    /// Wall-clock start time, used to tell a live process group from a pid that
    /// has been recycled since we wrote it down.
    pub fn start_secs(pid: u32) -> Option<u64> {
        bsdinfo(pid).map(|i| i.pbi_start_tvsec)
    }

    fn exe_path(pid: u32) -> String {
        let mut buf = vec![0u8; 4096];
        let n = unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr() as *mut libc::c_void, 4096) };
        if n <= 0 {
            return String::new();
        }
        String::from_utf8_lossy(&buf[..n as usize]).into_owned()
    }

    pub fn rss_kb(pid: u32) -> Option<u64> {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then(|| info.pti_resident_size / 1024)
    }

    /// v5 §3a. Cumulative CPU of one process. `proc_taskinfo` counts in
    /// nanoseconds; the watchdog's sibling on the tiers with a cgroup reads
    /// `cpu.stat` instead.
    pub fn cpu_millis(pid: u32) -> Option<u64> {
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then(|| (info.pti_total_user + info.pti_total_system) / 1_000_000)
    }

    /// `KERN_PROCARGS2`: `int argc`, the exec path, NUL padding, then `argc`
    /// NUL-terminated argv strings, then the environment (which we stop before —
    /// it is the one place a leaked token could show up in an event).
    fn argv(pid: u32) -> Vec<String> {
        let mut size: libc::size_t = 0;
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
        let ok = unsafe { libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) };
        if ok != 0 || size < 4 || size > 4 << 20 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size];
        let ok = unsafe {
            libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr() as *mut libc::c_void, &mut size, std::ptr::null_mut(), 0)
        };
        if ok != 0 {
            return Vec::new();
        }
        buf.truncate(size);
        parse_procargs2(&buf)
    }

    pub fn parse_procargs2(buf: &[u8]) -> Vec<String> {
        if buf.len() < 4 {
            return Vec::new();
        }
        let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]).max(0) as usize;
        let mut it = buf[4..].split(|b| *b == 0);
        // The exec path, then any number of empty strings used as padding.
        let _exec_path = it.next();
        let mut out = Vec::with_capacity(argc);
        for chunk in it {
            if out.len() == argc {
                break;
            }
            if chunk.is_empty() && out.is_empty() {
                continue; // still in the padding run
            }
            out.push(String::from_utf8_lossy(chunk).into_owned());
        }
        out
    }

    pub fn describe(pid: u32, root_pid: u32) -> Option<ProcInfo> {
        let i = bsdinfo(pid)?;
        let exe = exe_path(pid);
        let mut argv = argv(pid);
        if argv.is_empty() {
            let comm = i.pbi_comm.iter().take_while(|c| **c != 0).map(|c| *c as u8 as char).collect::<String>();
            argv = vec![if exe.is_empty() { comm } else { exe.clone() }];
        }
        Some(ProcInfo {
            pid,
            ppid: i.pbi_ppid,
            uid: i.pbi_uid,
            exe,
            argv,
            started_at: crate::rfc3339_millis(i.pbi_start_tvsec as i64 * 1000),
            rss_kb: rss_kb(pid),
            root_pid,
            pi_session: String::new(),
            tool_call_id: String::new(),
        })
    }

    // ---------------------------------------------------------- kqueue

    pub enum ProcEvent {
        Fork(u32),
        Exec(u32),
        /// The wait status is `Some` unless the kernel refused NOTE_EXITSTATUS.
        Exit(u32, Option<i32>),
    }

    /// One kqueue for the whole daemon. Every process in a watched group is
    /// registered individually (`NOTE_TRACK` is not supported on macOS 26).
    pub struct Kqueue {
        fd: libc::c_int,
        /// Pids currently registered, so a fork storm does not re-add them.
        tracked: Mutex<std::collections::HashSet<u32>>,
    }

    // The fd is only ever used with kevent(2), which is thread-safe.
    unsafe impl Send for Kqueue {}
    unsafe impl Sync for Kqueue {}

    impl Kqueue {
        pub fn open() -> Self {
            Self { fd: unsafe { libc::kqueue() }, tracked: Mutex::new(Default::default()) }
        }

        /// True when this call registered the pid (false: already tracked, or gone).
        pub fn track(&self, pid: u32) -> bool {
            if self.fd < 0 || !self.tracked.lock().unwrap().insert(pid) {
                return false;
            }
            let mut ev = libc::kevent {
                ident: pid as usize,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ENABLE,
                // NOTE_EXITSTATUS is what puts the exit code in `data`. XNU only
                // grants it to a process that could signal the target; drop it
                // and keep the plain registration if the kernel says no.
                fflags: libc::NOTE_EXIT | libc::NOTE_EXITSTATUS | libc::NOTE_FORK | libc::NOTE_EXEC,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            let mut r = unsafe { libc::kevent(self.fd, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES) {
                ev.fflags = libc::NOTE_EXIT | libc::NOTE_FORK | libc::NOTE_EXEC;
                r = unsafe { libc::kevent(self.fd, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
            }
            if r < 0 {
                // The process can already be gone; the sweep covers that case.
                tracing::debug!(pid, "kqueue track failed");
                self.tracked.lock().unwrap().remove(&pid);
                return false;
            }
            true
        }

        pub fn wait(&self, timeout: Duration) -> Vec<ProcEvent> {
            if self.fd < 0 {
                std::thread::sleep(timeout);
                return Vec::new();
            }
            let ts = libc::timespec {
                tv_sec: timeout.as_secs() as libc::time_t,
                tv_nsec: timeout.subsec_nanos() as libc::c_long,
            };
            let mut evs: [libc::kevent; 64] = unsafe { std::mem::zeroed() };
            let n = unsafe { libc::kevent(self.fd, std::ptr::null(), 0, evs.as_mut_ptr(), 64, &ts) };
            let mut out = Vec::new();
            for e in evs.iter().take(n.max(0) as usize) {
                let pid = e.ident as u32;
                if e.fflags & libc::NOTE_FORK != 0 {
                    out.push(ProcEvent::Fork(pid));
                }
                if e.fflags & libc::NOTE_EXEC != 0 {
                    out.push(ProcEvent::Exec(pid));
                }
                if e.fflags & libc::NOTE_EXIT != 0 {
                    // The kernel drops the registration on exit.
                    self.tracked.lock().unwrap().remove(&pid);
                    let status = (e.fflags & libc::NOTE_EXITSTATUS != 0).then_some(e.data as i32);
                    out.push(ProcEvent::Exit(pid, status));
                }
            }
            out
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn procargs2_parsing() {
            // argc=2, exec path, padding, argv[0], argv[1], then the environment.
            let mut b = 2i32.to_ne_bytes().to_vec();
            b.extend(b"/bin/echo\0\0\0");
            b.extend(b"echo\0hi\0");
            b.extend(b"SECRET=nope\0");
            assert_eq!(super::parse_procargs2(&b), vec!["echo", "hi"]);
            assert!(super::parse_procargs2(&[]).is_empty());
            assert!(super::parse_procargs2(&0i32.to_ne_bytes()).is_empty());
        }

        #[test]
        fn our_own_process_group_is_visible() {
            let pgid = unsafe { libc::getpgrp() } as u32;
            let pids = super::group_pids(pgid);
            let me = std::process::id();
            assert!(pids.contains(&me), "{pids:?} should contain {me}");
            assert_eq!(super::pgid_of(me), Some(pgid));
            let p = super::describe(me, pgid).expect("describe self");
            assert!(p.exe.contains("agent") || p.exe.contains("test"), "exe was {:?}", p.exe);
            assert!(!p.argv.is_empty());
        }
    }
}

// ------------------------------------------------------------------ Linux

#[cfg(not(target_os = "macos"))]
mod sys {
    use super::ProcInfo;

    fn stat_fields(pid: u32) -> Option<(u32, u32)> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // comm can contain spaces and parentheses; everything after the last ')'
        // is fixed-width.
        let rest = &s[s.rfind(')')? + 1..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        // rest[0] is state, so ppid is f[1] and pgrp f[2].
        Some((f.get(1)?.parse().ok()?, f.get(2)?.parse().ok()?))
    }

    pub fn pgid_of(pid: u32) -> Option<u32> {
        stat_fields(pid).map(|(_, pgrp)| pgrp)
    }

    /// Start time in clock ticks since boot (field 22 of `/proc/pid/stat`).
    /// Only ever compared with another reading of the same field, so the unit
    /// does not have to match the macOS one.
    pub fn start_secs(pid: u32) -> Option<u64> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = &s[s.rfind(')')? + 1..];
        rest.split_whitespace().nth(19)?.parse().ok()
    }

    pub fn group_pids(pgid: u32) -> Vec<u32> {
        group_pids_all(&[pgid]).remove(&pgid).unwrap_or_default()
    }

    /// Every watched group in one `/proc` scan. There is no kernel-side filter
    /// here (the netlink proc connector is root-only, and the container tier is
    /// not root), so the readdir is the feed: doing it once per tick instead of
    /// once per group is what keeps its cost flat as execs pile up.
    pub fn group_pids_all(pgids: &[u32]) -> std::collections::HashMap<u32, Vec<u32>> {
        let mut out: std::collections::HashMap<u32, Vec<u32>> = pgids.iter().map(|g| (*g, Vec::new())).collect();
        let Ok(rd) = std::fs::read_dir("/proc") else { return out };
        for pid in rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok()) {
            if let Some(v) = pgid_of(pid).and_then(|g| out.get_mut(&g)) {
                v.push(pid);
            }
        }
        out
    }

    pub fn rss_kb(pid: u32) -> Option<u64> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status_field(&status, "VmRSS:")?.parse().ok()
    }

    /// `utime + stime` out of `/proc/<pid>/stat` (fields 14 and 15 after the
    /// parenthesised comm), in clock ticks.
    pub fn cpu_millis(pid: u32) -> Option<u64> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let f: Vec<&str> = s[s.rfind(')')? + 1..].split_whitespace().collect();
        let ticks: u64 = f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?;
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        Some(ticks * 1000 / hz)
    }

    fn status_field(status: &str, key: &str) -> Option<String> {
        status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim().split_whitespace().next().unwrap_or("").to_string())
    }

    pub fn describe(pid: u32, root_pid: u32) -> Option<ProcInfo> {
        let (ppid, _) = stat_fields(pid)?;
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let argv: Vec<String> = std::fs::read(format!("/proc/{pid}/cmdline"))
            .unwrap_or_default()
            .split(|b| *b == 0)
            .filter(|c| !c.is_empty())
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect();
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.display().to_string()).unwrap_or_default();
        Some(ProcInfo {
            pid,
            ppid,
            uid: status_field(&status, "Uid:").and_then(|v| v.parse().ok()).unwrap_or(0),
            exe: exe.clone(),
            argv: if argv.is_empty() { vec![exe] } else { argv },
            started_at: crate::now_rfc3339(),
            rss_kb: status_field(&status, "VmRSS:").and_then(|v| v.parse().ok()),
            root_pid,
            pi_session: String::new(),
            tool_call_id: String::new(),
        })
    }

    /// Canary reads without eBPF (the container tier, or a kernel without BTF).
    /// Either watch is a kernel signal, so it sees a read whether or not the path
    /// ever appears on a command line; fanotify is tried first because its events
    /// name the pid that did the read, which is what turns the alert into one the
    /// timeline can attribute to a tool call.
    #[cfg(target_os = "linux")]
    pub fn spawn_canary_watch(mon: super::Monitor) {
        if fanotify_canary_watch(&mon) {
            return;
        }
        inotify_canary_watch(mon);
    }

    /// `false` when fanotify is not available to us: it needs CAP_SYS_ADMIN,
    /// which the microVM's root agent has and the container tier's uid 1000 does
    /// not. The caller then falls back, silently — a tier without the capability
    /// is not a misconfiguration.
    #[cfg(target_os = "linux")]
    fn fanotify_canary_watch(mon: &super::Monitor) -> bool {
        use std::ffi::CString;
        const META: usize = std::mem::size_of::<libc::fanotify_event_metadata>();
        let fd = unsafe { libc::fanotify_init(libc::FAN_CLOEXEC | libc::FAN_CLASS_NOTIF, libc::O_RDONLY as u32) };
        if fd < 0 {
            return false;
        }
        let mut marked = 0usize;
        for c in &mon.rules.canaries {
            let Ok(p) = CString::new(c.as_str()) else { continue };
            let r = unsafe {
                libc::fanotify_mark(
                    fd,
                    libc::FAN_MARK_ADD,
                    (libc::FAN_ACCESS | libc::FAN_OPEN) as _,
                    libc::AT_FDCWD,
                    p.as_ptr(),
                )
            };
            marked += usize::from(r == 0);
        }
        if marked == 0 {
            unsafe { libc::close(fd) };
            return false;
        }
        tracing::info!(files = marked, "canary fanotify watch attached");
        let mon = mon.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut last: std::collections::HashMap<String, std::time::Instant> = Default::default();
            loop {
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n <= 0 {
                    break;
                }
                let mut off = 0usize;
                while off + META <= n as usize {
                    let e: libc::fanotify_event_metadata =
                        unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast()) };
                    if (e.event_len as usize) < META {
                        break;
                    }
                    off += e.event_len as usize;
                    // fanotify hands over an open fd rather than a name; its
                    // /proc link is the only path we get, and it has to be
                    // closed or the watcher leaks one per read.
                    let path = std::fs::read_link(format!("/proc/self/fd/{}", e.fd))
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    if e.fd >= 0 {
                        unsafe { libc::close(e.fd) };
                    }
                    if !mon.rules.canaries.iter().any(|c| *c == path) {
                        continue;
                    }
                    // `cat` is one OPEN plus one ACCESS: one alert per read, not two.
                    let now = std::time::Instant::now();
                    if last.get(&path).is_some_and(|t| now.duration_since(*t) < std::time::Duration::from_secs(1)) {
                        continue;
                    }
                    last.insert(path.clone(), now);
                    // The pid is why this path exists: the alert lands on the
                    // tool call that owns the reader's process group.
                    mon.ev.alert(
                        &mon.corr_for_pid(e.pid as u32),
                        proto::Severity::Critical,
                        proto::rules::CANARY_READ,
                        format!("canary {path} was read"),
                        serde_json::json!({"path": path, "pid": e.pid, "source": "fanotify"}),
                    );
                }
            }
            tracing::warn!("fanotify canary watch stopped");
        });
        true
    }

    /// The fallback: the file is reported, the reader is not.
    #[cfg(target_os = "linux")]
    fn inotify_canary_watch(mon: super::Monitor) {
        use std::ffi::CString;
        use std::io::Read;
        use std::os::fd::FromRawFd;
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            return;
        }
        let mut names: std::collections::HashMap<i32, String> = Default::default();
        for c in &mon.rules.canaries {
            let Ok(p) = CString::new(c.as_str()) else { continue };
            let wd = unsafe { libc::inotify_add_watch(fd, p.as_ptr(), libc::IN_ACCESS | libc::IN_OPEN) };
            if wd >= 0 {
                names.insert(wd, c.clone());
            }
        }
        if names.is_empty() {
            unsafe { libc::close(fd) };
            return;
        }
        tracing::info!(files = names.len(), "canary inotify watch attached");
        std::thread::spawn(move || {
            let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
            let mut buf = [0u8; 4096];
            let mut last: std::collections::HashMap<i32, std::time::Instant> = Default::default();
            while let Ok(n) = f.read(&mut buf) {
                let mut off = 0;
                while off + std::mem::size_of::<libc::inotify_event>() <= n {
                    let ev: libc::inotify_event = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const _) };
                    off += std::mem::size_of::<libc::inotify_event>() + ev.len as usize;
                    // `cat` is one OPEN plus one ACCESS: one alert per read, not two.
                    let now = std::time::Instant::now();
                    if last.get(&ev.wd).is_some_and(|t| now.duration_since(*t) < std::time::Duration::from_secs(1)) {
                        continue;
                    }
                    last.insert(ev.wd, now);
                    if let Some(path) = names.get(&ev.wd) {
                        mon.ev.alert(
                            &mon.live_corr().unwrap_or_default(),
                            proto::Severity::Critical,
                            proto::rules::CANARY_READ,
                            format!("canary {path} was read"),
                            serde_json::json!({"path": path, "source": "inotify"}),
                        );
                    }
                }
            }
        });
    }

    /// How an exit is observed. `sched_process_exit` does not carry the status,
    /// and `curtask->exit_code` trips an assertion in bpftrace 0.20 (a bitfield
    /// in `task_struct`), so the status comes from `do_exit`'s argument — on a
    /// kernel with kprobes. Without them the tracepoint still reports the exit,
    /// only with a null `exit` (§1), which is what a bad probe would cost us:
    /// bpftrace refuses the *whole* program if one probe does not resolve.
    fn exit_probe() -> &'static str {
        let kprobes = std::path::Path::new("/sys/bus/event_source/devices/kprobe").exists()
            && std::fs::read_to_string("/proc/kallsyms").is_ok_and(|s| s.contains(" do_exit\n"));
        if kprobes {
            r#"kprobe:do_exit /pid == tid/ { printf("{\"t\":\"exit\",\"pid\":%d,\"st\":%d}\n", pid, arg0); }
"#
        } else {
            r#"tracepoint:sched:sched_process_exit /pid == tid/ { printf("{\"t\":\"exit\",\"pid\":%d}\n", pid); }
"#
        }
    }

    /// eBPF via bpftrace (D19). Only on a kernel with BTF and only when the
    /// binary is present — the remote tier's rootfs ships it, a container image
    /// normally does not. Exec and exit come through without sampling.
    /// Returns whether bpftrace was attached.
    #[cfg(target_os = "linux")]
    pub fn spawn_bpftrace(mon: super::Monitor) -> bool {
        use std::io::BufRead;
        // bpftrace refuses to run unprivileged and exits on the spot; returning
        // `true` then would hand it the lifecycle feed it never has (the sweep
        // stops announcing) — exactly what an unprivileged CI runner with
        // bpftrace installed hit.
        if unsafe { libc::geteuid() } != 0 {
            return false;
        }
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            return false;
        }
        let Some(bin) = crate::procmon::which("bpftrace") else { return false };
        // One program, four feeds: exec/exit (no sampling gap), opens under the
        // credential prefixes, and every TCP connect (the proxy is the only
        // legitimate destination). Everything else stays in the /proc sweep.
        const SCRIPT: &str = r#"
BEGIN { printf("{\"t\":\"ready\"}\n"); }
tracepoint:sched:sched_process_fork { printf("{\"t\":\"fork\",\"pid\":%d,\"ppid\":%d}\n", args->child_pid, args->parent_pid); }
tracepoint:sched:sched_process_exec { printf("{\"t\":\"exec\",\"pid\":%d,\"f\":\"%s\"}\n", pid, str(args->filename)); }
tracepoint:syscalls:sys_enter_openat
/ strncmp(str(args->filename), "/home/agent/.", 13) == 0 || strncmp(str(args->filename), "/etc/shadow", 11) == 0
  || strncmp(str(args->filename), "/proc/1/", 8) == 0 || strncmp(str(args->filename), "/root/", 6) == 0
  || strncmp(str(args->filename), "/var/run/", 9) == 0 || strncmp(str(args->filename), "/run/", 5) == 0 /
{ printf("{\"t\":\"open\",\"pid\":%d,\"c\":\"%s\",\"f\":\"%s\",\"fl\":%d}\n", pid, comm, str(args->filename), args->flags); }
tracepoint:syscalls:sys_enter_connect
{ $sa = (struct sockaddr_in *)args->uservaddr;
  if ($sa->sin_family == 2) {
    printf("{\"t\":\"connect\",\"pid\":%d,\"c\":\"%s\",\"ip\":\"%s\",\"port\":%d}\n", pid, comm, ntop(2, $sa->sin_addr.s_addr), (($sa->sin_port >> 8) | (($sa->sin_port & 0xff) << 8)));
  } }
tracepoint:syscalls:sys_enter_ptrace { printf("{\"t\":\"ptrace\",\"pid\":%d,\"c\":\"%s\"}\n", pid, comm); }
tracepoint:syscalls:sys_enter_mount  { printf("{\"t\":\"mount\",\"pid\":%d,\"c\":\"%s\"}\n", pid, comm); }
tracepoint:syscalls:sys_enter_setns  { printf("{\"t\":\"setns\",\"pid\":%d,\"c\":\"%s\"}\n", pid, comm); }
"#;
        let child = std::process::Command::new(bin)
            .args(["-q", "-e", &format!("{}{SCRIPT}", exit_probe())])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit()) // a compile error must be visible in the guest log
            .spawn();
        let Ok(mut child) = child else { return false };
        let Some(out) = child.stdout.take() else { return false };
        tracing::info!("bpftrace attached");
        // Our own syscalls and bpftrace's are noise to this feed — and worse than
        // noise: in the guest this agent is pid 1, so resolving an event by
        // reading `/proc/1/stat` trips the `/proc/1/` open probe, which produces
        // the next event, which reads `/proc/1/stat` again. Drop them at the door.
        let (me, tracer) = (std::process::id(), child.id());
        std::thread::spawn(move || {
            let mut lineage = super::Lineage::default();
            for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
                // The BEGIN probe: the program compiled and the tracepoints are
                // live. Only now does bpftrace own start/exit; until here the
                // sweep announced, so nothing from the first seconds is lost.
                if v["t"] == "ready" {
                    mon.inner.bpftrace_lifecycle.store(true, std::sync::atomic::Ordering::SeqCst);
                    continue;
                }
                let (Some(t), Some(pid)) = (v["t"].as_str(), v["pid"].as_u64()) else { continue };
                let pid = pid as u32;
                if pid == me || pid == tracer {
                    continue;
                }
                // fork/exec/exit are the lifecycle half and end here; everything
                // below is a syscall to attribute to the root it hands back.
                let Some(root) = lineage.on_event(&mon, t, pid, &v) else { continue };
                let corr = mon.corr_of(root);
                let comm = v["c"].as_str().unwrap_or("?");
                match t {
                    "open" => {
                        let f = v["f"].as_str().unwrap_or("");
                        // O_WRONLY|O_RDWR|O_CREAT|O_TRUNC: same values on x86_64 and aarch64.
                        let flags = v["fl"].as_u64().unwrap_or(0);
                        let write = flags & 0x3 != 0 || flags & 0x40 != 0 || flags & 0x200 != 0;
                        let op = if write { "write" } else { "read" };
                        mon.ev.emit(
                            &corr,
                            proto::EventType::FileAccess,
                            serde_json::json!({"pid": pid, "path": f, "op": op, "sensitive": true}),
                        );
                        for h in mon.rules.scan(f) {
                            // A login shell *reads* .profile; only a write to it is an alert.
                            if h.rule == proto::rules::SENSITIVE_PATH_WRITE && !write {
                                continue;
                            }
                            mon.ev.alert(&corr, h.severity, h.rule, format!("{comm} opened {f} for {op}"),
                                serde_json::json!({"pid": pid, "path": f, "evidence": {"source": "bpftrace", "flags": flags}}));
                        }
                    }
                    "connect" => {
                        let (ip, port) = (v["ip"].as_str().unwrap_or("?"), v["port"].as_u64().unwrap_or(0) as u16);
                        let allowed = super::dst_allowed(super::proxy_dst().as_ref(), ip, port);
                        mon.ev.emit(&corr, proto::EventType::NetConnect,
                            serde_json::json!({"pid": pid, "dst": ip, "port": port, "proto": "tcp", "allowed": allowed}));
                        if !allowed {
                            mon.ev.alert(
                                &corr,
                                proto::Severity::High,
                                proto::rules::SANDBOX_DENIED,
                                format!("{comm} tried to connect to {ip}:{port} bypassing the proxy"),
                                serde_json::json!({"pid": pid, "evidence": v}),
                            );
                        }
                    }
                    _ => {
                        let (rule, sev) = match t {
                            "ptrace" => (proto::rules::PTRACE_ATTEMPT, proto::Severity::High),
                            "mount" => (proto::rules::MOUNT_ATTEMPT, proto::Severity::High),
                            _ => (proto::rules::ESCAPE_PROBE, proto::Severity::Critical),
                        };
                        mon.ev.alert(
                            &corr,
                            sev,
                            rule,
                            format!("bpftrace saw {t} from {comm}"),
                            serde_json::json!({"pid": pid, "evidence": v}),
                        );
                    }
                }
            }
            // EOF: bpftrace refused the program or died. The sweep takes the
            // lifecycle back, and the canary watch replaces the open probe.
            mon.inner.bpftrace_lifecycle.store(false, std::sync::atomic::Ordering::SeqCst);
            tracing::warn!("bpftrace stopped; falling back to the /proc sweep and the inotify canary watch");
            spawn_canary_watch(mon);
        });
        true
    }
}

/// Wall-clock (macOS) or boot-relative (Linux) start time of a process. Two
/// readings only ever get compared with each other.
pub fn start_secs(pid: u32) -> Option<u64> {
    sys::start_secs(pid)
}

/// Every process of one group. v5: qafas's native tier moves them into a
/// cgroup leaf one pid at a time (`cgroup.procs` takes no lists), and a session
/// kills a stuck command by its members (`session::enforce_timeout`).
pub fn group_pids(pgid: u32) -> Vec<u32> {
    sys::group_pids(pgid)
}

/// First match for `name` on PATH.
#[allow(dead_code)]
pub fn which(name: &str) -> Option<std::path::PathBuf> {
    let path =
        std::env::var("PATH").unwrap_or_else(|_| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    path.split(':').map(|d| std::path::Path::new(d).join(name)).find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects everything the monitor emits, so a test can count alerts.
    fn recording() -> (Emitter, Arc<Mutex<Vec<proto::Event>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        (Emitter::new("h", "sbx", Arc::new(move |e| s.lock().unwrap().push(e))), seen)
    }

    /// v5 §3a. One kill, one alert. The remote tier produced 15 of them in a
    /// second for a single OOM because every sweep re-found the same group over
    /// the limit; the watchdog now remembers what it has already killed, and
    /// forgets it again when the exec is unwatched so a recycled pgid is not
    /// suppressed. The alert must also carry the killed group's own tool call.
    #[test]
    fn a_watchdog_kill_alerts_exactly_once_per_group() {
        let (ev, events) = recording();
        let mon = Monitor::new(ev, Rules::guest("/w", "/home/agent"));
        let alerts = || events.lock().unwrap().iter().filter(|e| e.r#type == EventType::SecurityAlert).count();

        // A pgid with no live process: killpg fails harmlessly and the
        // bookkeeping is what is under test.
        let pgid = 999_999u32;
        let corr = Corr { pi_session: "s1".into(), tool_call_id: "t1".into() };
        mon.watch(pgid, corr.clone());
        // 1 MiB budget, a sample far above it. Disk and pids off, so only memory trips.
        mon.set_budget(1024 * 1024, 0, 0, "/tmp".into());
        let empty = HashMap::new();

        mon.watchdog(64 * 1024 * 1024, &empty);
        assert_eq!(alerts(), 1, "the kill raises one alert");
        for _ in 0..14 {
            mon.watchdog(64 * 1024 * 1024, &empty);
        }
        assert_eq!(alerts(), 1, "later sweeps over the same group raise none");

        let a = events.lock().unwrap().iter().rev().find(|e| e.r#type == EventType::SecurityAlert).cloned().unwrap();
        assert_eq!(a.data["rule"], proto::rules::RESOURCE_LIMIT);
        assert_eq!((a.pi_session.as_str(), a.tool_call_id.as_str()), ("s1", "t1"), "the killed group's tool call");

        // A new exec on the same pgid is a new kill, not the old one.
        mon.unwatch(pgid);
        mon.watch(pgid, corr);
        mon.watchdog(64 * 1024 * 1024, &empty);
        assert_eq!(alerts(), 2);

        // v5 §3a, the `pids` dimension: over the group's size, one kill, one
        // alert that names the number. Memory is off here so only pids can trip.
        mon.set_budget(0, 0, 4, "/tmp".into());
        mon.unwatch(pgid);
        mon.watch(pgid, Corr::default());
        let sizes = HashMap::from([(pgid, 9usize)]);
        mon.watchdog(0, &sizes);
        assert_eq!(alerts(), 3, "nine processes against a limit of four is a kill");
        let a = events.lock().unwrap().iter().rev().find(|e| e.r#type == EventType::SecurityAlert).cloned().unwrap();
        assert_eq!(a.data["rule"], proto::rules::RESOURCE_LIMIT);
        assert_eq!(a.data["msg"], "process limit 4 hit (watchdog)", "{}", a.data);
        mon.watchdog(0, &sizes);
        assert_eq!(alerts(), 3, "and the sweeps after it stay quiet");

        // A group inside its size is left alone.
        mon.unwatch(pgid);
        mon.watch(pgid, Corr::default());
        mon.watchdog(0, &HashMap::from([(pgid, 4usize)]));
        assert_eq!(alerts(), 3, "exactly at the limit is not over it");

        // And nothing is armed once the kernel holds the limits.
        mon.set_budget(0, 0, 0, "/tmp".into());
        mon.unwatch(pgid);
        mon.watch(pgid, Corr::default());
        mon.watchdog(64 * 1024 * 1024, &sizes);
        assert_eq!(alerts(), 3, "a zero budget is not a budget of zero");
        mon.shutdown();
    }

    /// D19, the remote tier's feed. A synthetic bpftrace line sequence, replayed
    /// the way the reader thread would: one `process.start` and one
    /// `process.exit` per process, every one attributed to the exec that owns
    /// it, and nothing announced twice.
    ///
    /// The three shapes that broke it on Firecracker are all here: a fork the
    /// feed never saw (bash execs the last command of a subshell in place, so
    /// there is no fork to inherit a root from), a shebang's second exec for the
    /// same pid, and a process that exits inside one sweep tick — none of which
    /// `/proc` can be asked about after the fact.
    #[test]
    fn the_bpftrace_feed_reports_each_process_once() {
        let (ev, events) = recording();
        let mon = Monitor::new(ev, Rules::guest("/w", "/home/agent"));
        mon.shutdown(); // the sweep must not be the thing that reports these
        let root = std::process::id();
        mon.watch(root, Corr { pi_session: "s".into(), tool_call_id: "t".into() });

        let mut feed = Lineage::default();
        let line = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        let replay = |feed: &mut Lineage, s: &str| {
            let v = line(s);
            let (t, pid) = (v["t"].as_str().unwrap().to_string(), v["pid"].as_u64().unwrap() as u32);
            feed.on_event(&mon, &t, pid, &v);
        };

        // 7001: forked from the exec root, execs, exits — the ordinary case.
        replay(&mut feed, &format!(r#"{{"t":"fork","pid":7001,"ppid":{root}}}"#));
        replay(&mut feed, r#"{"t":"exec","pid":7001,"f":"/bin/sleep"}"#);
        // 7002: forked from 7001, so its root is inherited two levels down.
        replay(&mut feed, r#"{"t":"fork","pid":7002,"ppid":7001}"#);
        replay(&mut feed, r#"{"t":"exec","pid":7002,"f":"/bin/cat"}"#);
        // A shebang: the interpreter exec repeats the image for the same pid.
        replay(&mut feed, r#"{"t":"exec","pid":7002,"f":"/bin/cat"}"#);
        // Both exit inside the same tick, before any sweep could have seen them.
        replay(&mut feed, r#"{"t":"exit","pid":7002,"st":0}"#);
        replay(&mut feed, r#"{"t":"exit","pid":7001,"st":1792}"#);

        let evs = events.lock().unwrap();
        let of =
            |ty: EventType, pid: u64| evs.iter().filter(|e| e.r#type == ty && e.data["pid"] == pid).collect::<Vec<_>>();
        for pid in [7001u64, 7002] {
            let starts = of(EventType::ProcessStart, pid);
            assert_eq!(starts.len(), 1, "one process.start for {pid}: {starts:?}");
            assert_eq!(starts[0].data["root_pid"], root, "attributed to the exec");
            assert_eq!(
                (starts[0].pi_session.as_str(), starts[0].tool_call_id.as_str()),
                ("s", "t"),
                "and to its tool call",
            );
            assert_eq!(of(EventType::ProcessExit, pid).len(), 1, "one process.exit for {pid}");
        }
        assert_eq!(of(EventType::ProcessExit, 7001)[0].data["exit"], 7, "the wait status is decoded");
        assert_eq!(mon.unattributed_execs(), 0, "every exec found its root");
    }

    /// An exec whose fork the feed never saw and whose process is already gone
    /// is counted, not dropped on the floor: the `/proc` sweep is then the only
    /// thing that could report it, and an operator has to be able to see that.
    #[test]
    fn an_unattributable_exec_is_counted_rather_than_dropped() {
        let (ev, events) = recording();
        let mon = Monitor::new(ev, Rules::guest("/w", "/home/agent"));
        mon.shutdown();
        let mut feed = Lineage::default();
        let v = serde_json::json!({"t": "exec", "pid": 999_997, "f": "/bin/cat"});
        assert_eq!(feed.on_event(&mon, "exec", 999_997, &v), None);
        assert_eq!(mon.unattributed_execs(), 1);
        assert!(
            !events.lock().unwrap().iter().any(|e| e.r#type == EventType::ProcessStart),
            "and nothing is attributed to an exec it does not belong to",
        );
    }

    /// Children that live for less than a sweep interval must still be seen:
    /// that is the whole point of the kernel-driven path (kqueue on macOS).
    #[cfg(target_os = "macos")]
    #[test]
    fn short_lived_children_are_seen() {
        use std::os::unix::process::CommandExt;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let ev = Emitter::new("h", "sbx", Arc::new(move |e| s.lock().unwrap().push(e)));
        let mon = Monitor::new(ev, Rules::guest("/w", "/home/agent"));
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "sleep 0.05; ls / >/dev/null; /usr/bin/true; sleep 0.05"]).stdout(std::process::Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn");
        mon.watch(child.id(), Corr::default());
        child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        mon.unwatch(child.id());
        let evs = seen.lock().unwrap();
        let names: Vec<String> = evs
            .iter()
            .filter(|e| e.r#type == EventType::ProcessStart)
            .map(|e| {
                e.data["argv"]
                    .as_array()
                    .map(|a| a.iter().map(|v| v.as_str().unwrap_or("")).collect::<Vec<_>>().join(" "))
                    .unwrap_or_default()
            })
            .collect();
        assert!(names.iter().any(|n| n.starts_with("ls")), "ls must be reported: {names:?}");
        assert!(names.iter().any(|n| n.contains("true")), "true must be reported: {names:?}");
    }

    /// The monitor must see the children of an exec's process group, emit
    /// `process.start` for them carrying the owning tool call, and report the
    /// exits. Mirrors what `Spawner` does: the root is its own group leader.
    #[test]
    fn watching_a_group_reports_its_children() {
        use std::os::unix::process::CommandExt;

        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let ev = Emitter::new("h", "sbx", Arc::new(move |e| s.lock().unwrap().push(e)));
        let mon = Monitor::new(ev, Rules::guest("/w", "/home/agent"));

        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "sleep 2 & sleep 2"]).stdout(std::process::Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn");
        let root = child.id();
        mon.watch(root, Corr { pi_session: "p".into(), tool_call_id: "t".into() });

        // The two `sleep`s are children of the shell and inherit its group.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline && mon.snapshot().len() < 2 {
            std::thread::sleep(Duration::from_millis(50));
        }
        let snap = mon.snapshot();
        assert!(snap.iter().any(|p| p.pid == root), "the shell itself: {snap:?}");
        assert!(snap.len() >= 2, "its sleeps should be visible too: {snap:?}");
        assert!(snap.iter().all(|p| p.root_pid == root), "everything is attributed to the exec");
        assert!(snap.iter().any(|p| p.argv.iter().any(|a| a.contains("sleep"))), "argv: {snap:?}");

        let _ = child.kill();
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(300));
        mon.unwatch(root);
        mon.shutdown();

        let evs = seen.lock().unwrap();
        let starts: Vec<_> = evs.iter().filter(|e| e.r#type == EventType::ProcessStart).collect();
        assert!(starts.len() >= 2, "one process.start each: {starts:?}");
        assert!(starts.iter().all(|e| e.pi_session == "p" && e.tool_call_id == "t"));
        assert!(evs.iter().any(|e| e.r#type == EventType::ProcessExit && e.data["pid"] == root));
    }

    /// N2: the connection to the egress proxy is the one the policy requires,
    /// so it must not raise `sandbox.denied`. Anything else still does.
    #[test]
    fn the_proxy_itself_is_not_a_bypass() {
        assert_eq!(parse_proxy("http://172.16.11.1:3128"), Some(("172.16.11.1".into(), 3128)));
        assert_eq!(parse_proxy("http://172.16.11.1:3128/"), Some(("172.16.11.1".into(), 3128)));
        assert_eq!(parse_proxy("172.16.3.1:3128"), Some(("172.16.3.1".into(), 3128)));
        assert_eq!(parse_proxy("http://nope"), None);

        let proxy = parse_proxy("http://172.16.11.1:3128");
        assert!(dst_allowed(proxy.as_ref(), "172.16.11.1", 3128), "the proxy is the allowed path");
        assert!(dst_allowed(proxy.as_ref(), "127.0.0.1", 7777), "loopback stays in the sandbox");
        assert!(!dst_allowed(proxy.as_ref(), "1.1.1.1", 53), "direct DNS is a bypass");
        assert!(!dst_allowed(proxy.as_ref(), "172.16.11.1", 22), "another port on the proxy host is a bypass");
        assert!(!dst_allowed(None, "1.1.1.1", 53));
    }

    /// 18: `process.exit` must carry the exit code or the signal.
    #[test]
    fn exit_status_is_decoded() {
        assert_eq!(decode_status(7 << 8), (Some(7), None));
        assert_eq!(decode_status(0), (Some(0), None));
        assert_eq!(decode_status(libc::SIGKILL), (Some(-1), Some("KILL".into())));
        assert_eq!(decode_status(libc::SIGSYS), (Some(-1), Some("SYS".into())));
    }

    /// 18, on the feed that reports it: kqueue's NOTE_EXITSTATUS.
    #[cfg(target_os = "macos")]
    #[test]
    fn kqueue_reports_the_exit_code() {
        use std::os::unix::process::CommandExt;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let ev = Emitter::new("h", "sbx", Arc::new(move |e| s.lock().unwrap().push(e)));
        let mon = Monitor::new(ev, Rules::guest("/w", "/home/agent"));
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "sleep 0.2; exit 7"]);
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn");
        let root = child.id();
        mon.watch(root, Corr::default());
        child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        mon.unwatch(root);
        mon.shutdown();
        let evs = seen.lock().unwrap();
        let exit = evs
            .iter()
            .find(|e| e.r#type == EventType::ProcessExit && e.data["pid"] == root)
            .unwrap_or_else(|| panic!("no process.exit for {root}: {evs:?}"));
        assert_eq!(exit.data["exit"], 7, "{}", exit.data);
    }
}
