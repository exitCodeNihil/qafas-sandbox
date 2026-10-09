//! Warm pool (D1). Nothing cold-boots a Linux userland fast enough, so the
//! answer to "fast start" is "already started".
//!
//! Key is `template|workspace_path`, because a podman sandbox has the workspace
//! bind-mounted at create time. The first request for a new cwd is therefore
//! cold; PLAN §11 accepts that for the POC. A microVM pool is workspace-agnostic
//! (`pool_by_workspace() == false`), so there the key *is* the template.
//!
//! v4 (§3a "warm pool policy"): how many entries a template keeps is
//! `max(warm, recent)`, `base` keeps `SBX_POOL_SIZE` unless a `PUT` says
//! otherwise, and one background pass both tops up what is short and tears
//! down what is over.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use proto::{EventType, PoolStat, PoolStats};
use serde_json::json;
use tokio::sync::Mutex;

use crate::backend::{Backend, Sandbox, SnapshotRef, Spec};
use crate::events::{new_event, Bus, Corr};
use crate::snapshots::BASE;

/// `sbx_<8>`: the tail of a ULID, which is the random half. Short enough to read
/// in a log line; 40 bits is plenty for the sandboxes one host ever holds.
pub fn new_id() -> String {
    let u = ulid::Ulid::new().to_string().to_lowercase();
    format!("sbx_{}", &u[u.len() - 8..])
}

fn key(template: &str, workspace: &str) -> String {
    format!("{template}|{workspace}")
}

/// How often the policy is re-applied. A template's recency lapsing is what
/// makes its warm entries go away, so this is also the eviction interval.
const RECONCILE_EVERY: Duration = Duration::from_secs(30);

/// How long an acquire waits for a warm sandbox to say it is alive. A warm guest
/// answered `/healthz` before it was pooled, so this is a liveness question and
/// not a boot one: a second is generous, and a dead one refuses at once.
const DEAD_WARM_PROBE: Duration = Duration::from_secs(1);

/// v4 §3a warm-pool policy, straight from the config.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// `base`'s default target: `SBX_POOL_SIZE`. `PUT /snapshots/base` overrides it.
    pub base: u32,
    /// A template acquired within this many seconds holds a recency slot
    /// (`SBX_POOL_RECENT_SECS`).
    pub recent_secs: u64,
    /// At most this many templates hold one (`SBX_POOL_RECENT_MAX`).
    pub recent_max: usize,
}

/// The number of warm sandboxes one template should have, given the `warm`
/// already resolved for it. `base` is that number flat — it is always pooled,
/// so recency has nothing to add; every other template is floored at 1 for as
/// long as it holds a recency slot.
pub fn target_for(template: &str, warm: u32, recent: bool) -> u32 {
    if template == BASE {
        warm
    } else {
        warm.max(u32::from(recent))
    }
}

/// `warm` for a template nobody has set one for: `SBX_POOL_SIZE` for `base`
/// (§3a: "its default is SBX_POOL_SIZE"), nothing for the rest.
pub fn default_warm(template: &str, p: &Policy) -> u32 {
    if template == BASE {
        p.base
    } else {
        0
    }
}

/// Which templates hold a recency slot, given `(template, seconds since it was
/// last acquired)`: those inside `recent_secs`, at most `recent_max` of them,
/// least recently used losing it first.
pub fn recency_slots(mut used: Vec<(String, u64)>, p: &Policy) -> HashSet<String> {
    used.retain(|(_, age)| *age < p.recent_secs);
    // Ties broken by name so the bound is deterministic (and testable).
    used.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    used.truncate(p.recent_max);
    used.into_iter().map(|(n, _)| n).collect()
}

/// One pool key: the warm queue plus everything a refill needs to boot another.
struct Slot {
    template: String,
    workspace: String,
    image: String,
    snapshot: Option<SnapshotRef>,
    warm: VecDeque<Sandbox>,
    /// v4: when this key was last *acquired* — `None` for one the refill made
    /// but nobody has asked for. Recency is about demand, not about supply.
    last_acquired: Option<Instant>,
}

/// design: one mutex over the whole map, and deliberately so — no caller holds
/// the guard across an `await` (`acquire` drops it around every health probe,
/// `spawn_refill` around every boot), so a critical section is a handful of
/// `HashMap` operations. A per-key lock would buy ordering bugs, not throughput.
#[derive(Default)]
struct Inner {
    slots: HashMap<String, Slot>,
    refilling: HashSet<String>,
    /// v4 `warm` per template, from the snapshot store and `PUT /snapshots/{name}`.
    warm: HashMap<String, u32>,
}

impl Inner {
    /// Seconds since each template was last acquired (the freshest of its keys).
    fn ages(&self) -> Vec<(String, u64)> {
        let mut m: HashMap<&str, u64> = HashMap::new();
        for s in self.slots.values() {
            let Some(t) = s.last_acquired else { continue };
            let age = t.elapsed().as_secs();
            let e = m.entry(&s.template).or_insert(age);
            *e = (*e).min(age);
        }
        m.into_iter().map(|(k, a)| (k.to_string(), a)).collect()
    }

    fn target(&self, template: &str, recent: &HashSet<String>, p: &Policy) -> u32 {
        let warm = self.warm.get(template).copied().unwrap_or_else(|| default_warm(template, p));
        target_for(template, warm, recent.contains(template))
    }
}

#[derive(Clone)]
pub struct Pool {
    inner: Arc<Mutex<Inner>>,
    backend: Arc<dyn Backend>,
    policy: Policy,
    bus: Bus,
    host_id: String,
    /// v5 §3a. What a warm sandbox is booted with (`medium`), before `acquire`
    /// resizes it to whatever the request asked for.
    default_limits: proto::SandboxLimits,
}

impl Pool {
    pub fn new(
        backend: Arc<dyn Backend>,
        policy: Policy,
        bus: Bus,
        host_id: String,
        default_limits: proto::SandboxLimits,
    ) -> Self {
        let p = Self { inner: Default::default(), backend, policy, bus, host_id, default_limits };
        p.spawn_maintainer();
        p
    }

    /// Destroys every warm sandbox built from `template` (its snapshot is gone).
    pub async fn drain_template(&self, template: &str) {
        let stale: Vec<Sandbox> = {
            let mut g = self.inner.lock().await;
            g.warm.remove(template);
            let keys: Vec<String> =
                g.slots.iter().filter(|(_, s)| s.template == template).map(|(k, _)| k.clone()).collect();
            keys.into_iter().flat_map(|k| g.slots.remove(&k).map(|s| s.warm).unwrap_or_default()).collect()
        };
        for sb in stale {
            let _ = self.backend.destroy(&sb).await;
        }
    }

    fn key(&self, template: &str, workspace: &str) -> String {
        key(template, if self.backend.pool_by_workspace() { workspace } else { "" })
    }

    /// v4 `PUT /snapshots/{name}`: the per-template target, plus a nudge so the
    /// new number takes effect without waiting for the next pass.
    pub async fn set_warm(&self, template: &str, warm: u32) {
        self.inner.lock().await.warm.insert(template.to_string(), warm);
        self.reconcile().await;
    }

    /// The `warm` targets the store knows about, loaded at start.
    pub async fn load_warm(&self, targets: impl IntoIterator<Item = (String, u32)>) {
        let mut g = self.inner.lock().await;
        g.warm.extend(targets);
    }

    /// v4 `SnapshotInfo.warm_ready`: warm sandboxes of this template right now.
    pub async fn warm_ready(&self, template: &str) -> u32 {
        self.inner.lock().await.slots.values().filter(|s| s.template == template).map(|s| s.warm.len() as u32).sum()
    }

    fn spawn_maintainer(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RECONCILE_EVERY).await;
                this.reconcile().await;
            }
        });
    }

    /// One pass of the policy: destroy what is above target, top up what is
    /// below it, forget keys that are neither. This is the whole evictor — a
    /// template stops being warm because it stopped being recent.
    pub async fn reconcile(&self) {
        let mut extra: Vec<Sandbox> = Vec::new();
        let mut short: Vec<(String, String, String, Option<SnapshotRef>)> = Vec::new();
        {
            let mut g = self.inner.lock().await;
            let recent = recency_slots(g.ages(), &self.policy);
            let targets: HashMap<String, u32> =
                g.slots.values().map(|s| (s.template.clone(), g.target(&s.template, &recent, &self.policy))).collect();
            g.slots.retain(|_, s| {
                let t = targets[&s.template] as usize;
                while s.warm.len() > t {
                    extra.extend(s.warm.pop_back());
                }
                if s.warm.len() < t {
                    short.push((s.template.clone(), s.workspace.clone(), s.image.clone(), s.snapshot.clone()));
                }
                // An empty key nobody wants any more stops holding a recency slot.
                t > 0 || !s.warm.is_empty()
            });
        }
        for sb in extra {
            tracing::info!(sandbox_id = %sb.id, "warm sandbox above target; evicting");
            let _ = self.backend.destroy(&sb).await;
        }
        for (template, workspace, image, snapshot) in short {
            self.spawn_refill(template, workspace, image, snapshot);
        }
    }

    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.backend
    }

    async fn create(
        &self,
        template: &str,
        workspace: &str,
        egress_allow: &[String],
        image: &str,
        snapshot: Option<crate::backend::SnapshotRef>,
        limits: proto::SandboxLimits,
    ) -> anyhow::Result<Sandbox> {
        let spec = Spec {
            id: new_id(),
            template: template.to_string(),
            workspace_path: workspace.to_string(),
            egress_allow: egress_allow.to_vec(),
            image: image.to_string(),
            snapshot,
            env: Default::default(),
            // A warm sandbox is created before any session claims it.
            pi_session: String::new(),
            limits,
        };
        let id = spec.id.clone();
        let ev = |ty, data| new_event(&self.host_id, &id, &Corr::default(), ty, data);
        let _ = self.bus.send(ev(
            EventType::SandboxCreated,
            json!({"template": template, "backend": self.backend.name(), "workspace": workspace}),
        ));
        match self.backend.create(spec).await {
            Ok(sb) => {
                let _ = self.bus.send(ev(EventType::SandboxReady, json!({"boot_ms": sb.boot_ms})));
                Ok(sb)
            }
            Err(e) => {
                let _ = self.bus.send(ev(EventType::Error, json!({"msg": e.to_string()})));
                Err(e)
            }
        }
    }

    /// Pops a warm sandbox, or pays for a cold one, then refills in the
    /// background either way.
    pub async fn acquire(
        &self,
        template: &str,
        workspace: &str,
        egress_allow: &[String],
        image: &str,
        snapshot: Option<crate::backend::SnapshotRef>,
        limits: &proto::SandboxLimits,
    ) -> anyhow::Result<(Sandbox, bool)> {
        let k = self.key(template, workspace);
        {
            let mut g = self.inner.lock().await;
            let s = g.slots.entry(k.clone()).or_insert_with(|| Slot {
                template: template.to_string(),
                workspace: String::new(),
                image: String::new(),
                snapshot: None,
                warm: VecDeque::new(),
                last_acquired: None,
            });
            // The refill has to boot the same thing: for a snapshot template the
            // image and the snapshot are what the key means, not a detail of the
            // request that happened to arrive first.
            s.workspace = workspace.to_string();
            s.image = image.to_string();
            s.snapshot = snapshot.clone();
            s.last_acquired = Some(Instant::now());
        }
        // A warm VM can have died since it was booted (a panic, a kill, an OOM),
        // and handing one out is a 201 with a token for nothing: the client's
        // first exec is what discovers it. Ask the guest before promising it, and
        // keep asking down the queue.
        let mut warm = None;
        loop {
            // The guard is taken and dropped inside the block: the probe below can
            // take a second and nothing else may wait on the whole pool for it.
            let next = {
                let mut g = self.inner.lock().await;
                g.slots.get_mut(&k).and_then(|s| s.warm.pop_front())
            };
            let Some(sb) = next else { break };
            if crate::backend::wait_healthy(&sb.connector, DEAD_WARM_PROBE).await.is_ok() {
                warm = Some(sb);
                break;
            }
            tracing::warn!(sandbox_id = %sb.id, template, "warm sandbox is not answering; discarding it");
            let _ = self.bus.send(new_event(
                &self.host_id,
                &sb.id,
                &Corr::default(),
                EventType::Error,
                json!({"msg": "warm sandbox was dead on acquire", "template": template}),
            ));
            let _ = self.backend.destroy(&sb).await;
        }
        let out = match warm {
            Some(sb) => {
                // v5 §3a "resize at acquire": one warm pool at the default size,
                // moved onto the request's ceilings before the client ever sees
                // it. A resize we cannot do is a create failure, not a sandbox
                // handed out with somebody else's limits.
                self.backend.apply_limits(&sb, limits).await?;
                (sb, true)
            }
            None => (self.create(template, workspace, egress_allow, image, snapshot.clone(), *limits).await?, false),
        };
        self.spawn_refill(template.to_string(), workspace.to_string(), image.to_string(), snapshot);
        Ok(out)
    }

    pub fn spawn_refill(
        &self,
        template: String,
        workspace: String,
        image: String,
        snapshot: Option<crate::backend::SnapshotRef>,
    ) {
        let this = self.clone();
        tokio::spawn(async move {
            let k = this.key(&template, &workspace);
            // A workspace-agnostic backend boots without one; the tar names it later.
            let workspace = if this.backend.pool_by_workspace() { workspace } else { String::new() };
            if !this.inner.lock().await.refilling.insert(k.clone()) {
                return; // another refill is already on it
            }
            loop {
                let (have, want) = {
                    let g = this.inner.lock().await;
                    let recent = recency_slots(g.ages(), &this.policy);
                    let have = g.slots.get(&k).map_or(0, |s| s.warm.len()) as u32;
                    (have, g.target(&template, &recent, &this.policy))
                };
                if have >= want {
                    break;
                }
                // Warm sandboxes are always the default size; `acquire` resizes.
                match this.create(&template, &workspace, &[], &image, snapshot.clone(), this.default_limits).await {
                    Ok(sb) => {
                        let mut g = this.inner.lock().await;
                        let s = g.slots.entry(k.clone()).or_insert_with(|| Slot {
                            template: template.clone(),
                            workspace: workspace.clone(),
                            image: image.clone(),
                            snapshot: snapshot.clone(),
                            warm: VecDeque::new(),
                            last_acquired: None,
                        });
                        s.warm.push_back(sb);
                        let size = s.warm.len();
                        drop(g);
                        let _ = this.bus.send(new_event(
                            &this.host_id,
                            "",
                            &Corr::default(),
                            EventType::PoolRefill,
                            json!({"template": template, "size": size}),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, template, workspace, "pool refill failed");
                        break;
                    }
                }
            }
            this.inner.lock().await.refilling.remove(&k);
        });
    }

    /// v4 §3a: keyed by template name, not by pool key. On a workspace-keyed
    /// pool (podman) one template holds several keys, and `reconcile` gives each
    /// of them the template's target — so the template's target is that number
    /// once per key, which is what makes `warm <= target` true here as well.
    pub async fn stats(&self) -> PoolStats {
        let g = self.inner.lock().await;
        let recent = recency_slots(g.ages(), &self.policy);
        let mut out = PoolStats::new();
        for s in g.slots.values() {
            let e = out.entry(s.template.clone()).or_insert(PoolStat { warm: 0, target: 0, restore: false });
            e.warm += s.warm.len() as u32;
            e.target += g.target(&s.template, &recent, &self.policy);
            e.restore |= s.snapshot.as_ref().is_some_and(|r| r.is_restore());
        }
        out
    }

    /// Destroys every warm sandbox. Called on shutdown.
    pub async fn drain(&self) {
        let all: Vec<Sandbox> = self.inner.lock().await.slots.drain().flat_map(|(_, s)| s.warm).collect();
        for sb in all {
            if let Err(e) = self.backend.destroy(&sb).await {
                tracing::warn!(error = %e, id = sb.id, "drain failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{BoxFut, Connector};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Answers `/healthz` and nothing else, so a warm sandbox in these tests is
    /// alive in the same way a real one is — `acquire` now asks.
    async fn healthz() -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    // Read the request first: closing on an unread socket resets
                    // it, and the probe's own write is what loses the race.
                    let _ = s.read(&mut [0u8; 512]).await;
                    let _ = s.write_all(b"HTTP/1.0 200 OK\r\ncontent-length: 0\r\n\r\n").await;
                    let _ = s.shutdown().await;
                });
            }
        });
        addr
    }

    struct Fake(AtomicU32, SocketAddr);

    impl Backend for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn create(&self, spec: Spec) -> BoxFut<'_, anyhow::Result<Sandbox>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(Sandbox {
                    id: spec.id,
                    template: spec.template,
                    workspace_path: spec.workspace_path,
                    connector: Connector::Tcp(self.1),
                    agent_token: None,
                    peer_ip: None,
                    created_at: "t".into(),
                    ready_at: Some("t".into()),
                    boot_ms: 1,
                })
            })
        }
        fn destroy(&self, _sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    const MINI: proto::SandboxLimits = proto::SandboxLimits { cpus: 1.0, mem_mib: 1024, disk_mib: 1024, pids: 256 };

    fn policy(base: u32) -> Policy {
        Policy { base, recent_secs: 3600, recent_max: 4 }
    }

    async fn settle(pool: &Pool, want: u32) {
        for _ in 0..200 {
            if pool.stats().await.values().map(|s| s.warm).sum::<u32>() >= want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("pool never reached {want}: {:?}", pool.stats().await);
    }

    #[tokio::test]
    async fn first_acquire_is_cold_then_the_pool_refills_and_serves_warm() {
        let backend = Arc::new(Fake(AtomicU32::new(0), healthz().await));
        let pool = Pool::new(backend.clone(), policy(2), crate::events::bus(), "h".into(), MINI);

        let (_sb, warm) = pool.acquire("base", "/w", &[], "", None, &MINI).await.unwrap();
        assert!(!warm, "nothing was pooled yet, so the first one is cold");
        settle(&pool, 2).await;
        let st = pool.stats().await;
        // v4: keyed by template, not by `template|workspace`.
        assert_eq!((st["base"].warm, st["base"].target, st["base"].restore), (2, 2, false));

        let (_sb, warm) = pool.acquire("base", "/w", &[], "", None, &MINI).await.unwrap();
        assert!(warm, "second acquire comes out of the pool");
        settle(&pool, 2).await;

        // A different workspace is a different key, and starts cold again.
        let (_sb, warm) = pool.acquire("base", "/other", &[], "", None, &MINI).await.unwrap();
        assert!(!warm);
        settle(&pool, 4).await;
        assert_eq!(pool.stats().await.len(), 1, "both keys are the same template");
        assert_eq!(pool.stats().await["base"].warm, 4);

        pool.drain().await;
        assert!(pool.stats().await.values().all(|s| s.warm == 0));
        assert!(backend.0.load(Ordering::SeqCst) >= 5);
    }

    /// §3a "warm pool policy": `max(warm, recent)`, and `base` defaults to
    /// `SBX_POOL_SIZE` but takes a `PUT` like anything else.
    #[test]
    fn the_target_is_the_policy_of_the_contract() {
        let p = policy(2);
        // base: SBX_POOL_SIZE until somebody says otherwise, and no recency term.
        assert_eq!(default_warm(BASE, &p), 2);
        assert_eq!(target_for(BASE, default_warm(BASE, &p), false), 2);
        assert_eq!(target_for(BASE, 9, true), 9, "PUT /snapshots/base wins over the default");
        assert_eq!(target_for(BASE, 0, true), 0, "and can switch the base pool off");
        // Everything else starts at nothing and is the max of the two.
        assert_eq!(default_warm("node", &p), 0);
        assert_eq!(target_for("node", 0, false), 0, "cold when neither says otherwise");
        assert_eq!(target_for("node", 0, true), 1, "recently used keeps one ready");
        assert_eq!(target_for("node", 3, false), 3, "an explicit warm needs no recency");
        assert_eq!(target_for("node", 3, true), 3, "and recency does not add to it");
    }

    /// The recency slot is bounded and the least recently used loses it.
    #[test]
    fn recency_is_bounded_and_lru() {
        let p = Policy { base: 2, recent_secs: 3600, recent_max: 2 };
        let used = |v: &[(&str, u64)]| v.iter().map(|(n, a)| (n.to_string(), *a)).collect::<Vec<_>>();

        assert!(recency_slots(used(&[("a", 10)]), &p).contains("a"));
        assert!(!recency_slots(used(&[("a", 3600)]), &p).contains("a"), "the window is exclusive");
        assert!(recency_slots(used(&[("a", 3599)]), &p).contains("a"));

        // Three inside the window, room for two: the oldest is dropped.
        let s = recency_slots(used(&[("a", 30), ("b", 10), ("c", 20)]), &p);
        assert_eq!(s.len(), 2);
        assert!(s.contains("b") && s.contains("c") && !s.contains("a"));

        // Out-of-window entries never take a slot from an in-window one.
        let s = recency_slots(used(&[("old", 99_999), ("a", 50), ("b", 40)]), &p);
        assert!(s.contains("a") && s.contains("b") && !s.contains("old"));
    }

    /// B-bug: a warm entry whose guest died must not be handed out as a 201 with
    /// a token for nothing.
    #[tokio::test]
    async fn a_dead_warm_sandbox_is_discarded_instead_of_handed_out() {
        // Port 1: nothing is listening, which is what a killed guest looks like.
        let backend = Arc::new(Fake(AtomicU32::new(0), "127.0.0.1:1".parse().unwrap()));
        let pool = Pool::new(backend.clone(), policy(1), crate::events::bus(), "h".into(), MINI);

        let (_sb, warm) = pool.acquire("base", "/w", &[], "", None, &MINI).await.unwrap();
        assert!(!warm, "nothing was pooled yet");
        settle(&pool, 1).await;

        let (_sb, warm) = pool.acquire("base", "/w", &[], "", None, &MINI).await.unwrap();
        assert!(!warm, "the pooled entry was dead, so this acquire paid for a cold one");
        assert_eq!(pool.warm_ready("base").await, 0, "and the dead entry is out of the queue");
    }

    /// A template with an explicit `warm` fills without ever being acquired, and
    /// dropping the number tears the extras down again.
    #[tokio::test]
    async fn set_warm_fills_and_shrinks_a_template() {
        let backend = Arc::new(Fake(AtomicU32::new(0), healthz().await));
        let pool = Pool::new(backend.clone(), policy(0), crate::events::bus(), "h".into(), MINI);

        pool.set_warm("node", 2).await;
        pool.spawn_refill("node".into(), String::new(), "img".into(), None);
        settle(&pool, 2).await;
        assert_eq!(pool.stats().await["node"].target, 2);
        assert_eq!(pool.warm_ready("node").await, 2);

        pool.set_warm("node", 0).await;
        // Not recent-exempt: `set_warm` reconciles, which is also the evictor.
        for _ in 0..200 {
            if pool.warm_ready("node").await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(pool.warm_ready("node").await, 0, "above-target entries are torn down");
    }

    /// A workspace-keyed pool (podman) gives one template several keys, and
    /// `reconcile` fills each of them to the template's target. `stats` reports
    /// the sum of the queues, so it has to report the sum of the targets too —
    /// otherwise the dashboard shows `warm 2 / target 1` and reads as a bug.
    #[tokio::test]
    async fn warm_never_reads_higher_than_target_across_a_templates_keys() {
        let backend = Arc::new(Fake(AtomicU32::new(0), healthz().await));
        let pool = Pool::new(backend.clone(), policy(1), crate::events::bus(), "h".into(), MINI);
        assert!(pool.backend().pool_by_workspace(), "this is the tier with several keys");

        for ws in ["/w/one", "/w/two"] {
            pool.acquire("base", ws, &[], "", None, &MINI).await.unwrap();
        }
        settle(&pool, 2).await;

        let s = &pool.stats().await["base"];
        assert_eq!(s.warm, 2, "one warm sandbox per key");
        assert!(s.warm <= s.target, "warm {} must never exceed target {}", s.warm, s.target);
    }
}
