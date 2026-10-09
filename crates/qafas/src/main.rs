//! qafas: the host daemon. `serve` is the API, the tiers and the pool;
//! `proxy` is the same binary running as the egress proxy (a container in the
//! podman backend, in process in the native and Firecracker ones); `doctor`
//! reports what this host can do; `bench` is a thin latency probe.

mod api;
mod backend;
mod bench;
mod config;
mod doctor;
mod events;
mod livetable;
mod metrics;
mod policy;
mod pool;
mod preview;
mod proxy;
mod sblog;
mod scan;
mod seatbelt;
mod shim;
mod snapshots;
mod tls;
mod tools;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use config::Config;

#[derive(Parser)]
#[command(name = "qafas", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the sandbox API (default).
    Serve,
    /// Run the egress proxy.
    Proxy {
        /// Where to POST `egress.*` events; omit to only log them.
        #[arg(long)]
        sink: Option<String>,
        #[arg(long, default_value = "0.0.0.0:3128")]
        listen: SocketAddr,
        /// Also relay CONNECTs from the host onto the sandbox network (rootful podman on Linux).
        #[arg(long, requires = "relay_net")]
        relay: Option<SocketAddr>,
        /// The sandbox network, e.g. 10.89.0.0/24: relay peers must be outside it, targets inside.
        #[arg(long)]
        relay_net: Option<String>,
    },
    /// Report what this host can serve, and why not, for the rest.
    Doctor {
        /// `{checks, caps, configured, serving}` for installers (v4c §3a).
        #[arg(long)]
        json: bool,
    },
    /// The native tier's in-sandbox agent (spawned by `serve`, never by hand).
    Shim {
        #[arg(long)]
        socket: PathBuf,
    },
    /// Measure exec round trip against a running daemon.
    Bench {
        /// Base URL of a running qafas.
        #[arg(long, default_value = "http://127.0.0.1:7700")]
        url: String,
        #[arg(long, default_value = "auto")]
        isolation: String,
        #[arg(long, default_value_t = 200)]
        count: u32,
        /// Workspace to give the sandbox; defaults to the current directory.
        #[arg(long)]
        workspace: Option<String>,
    },
}

fn init_logging() {
    // Structured JSON with the fields the runbooks grep for. `RUST_LOG=info` by
    // default; `SBX_LOG_PRETTY=1` for a human at a terminal.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    if std::env::var("SBX_LOG_PRETTY").as_deref() == Ok("1") {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt().json().flatten_event(true).with_env_filter(filter).init();
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cmd = Cli::parse().cmd.unwrap_or(Cmd::Serve);
    // The shim runs inside the sandbox with a curated environment and no config.
    if let Cmd::Shim { socket } = cmd {
        return shim::run(socket).await;
    }
    let cfg = Arc::new(Config::load()?);
    match cmd {
        Cmd::Proxy { sink, listen, relay, relay_net } => {
            if let (Some(relay), Some(net)) = (relay, relay_net) {
                let net =
                    proxy::parse_cidr(&net).ok_or_else(|| anyhow::anyhow!("--relay-net {net:?} is not a CIDR"))?;
                let l = tokio::net::TcpListener::bind(relay).await?;
                tracing::info!(%relay, ?net, "agent relay listening");
                tokio::spawn(async move {
                    if let Err(e) = proxy::serve_relay(l, net).await {
                        tracing::error!(error = %e, "agent relay died");
                    }
                });
            }
            // The daemon's own certificate, when its API (and so the sink) is TLS.
            let sink_ca = std::env::var("SBX_SINK_CA").ok().filter(|p| !p.is_empty()).map(String::into_bytes);
            proxy::run(listen, &cfg.policy, sink, sink_ca, cfg.token.clone(), cfg.host_id.clone()).await
        }
        Cmd::Doctor { json } => doctor::run(cfg, json).await,
        Cmd::Shim { .. } => unreachable!("handled above"),
        Cmd::Bench { url, isolation, count, workspace } => bench::run(&cfg, &url, &isolation, count, workspace).await,
        Cmd::Serve => serve(cfg).await,
    }
}

async fn serve(cfg: Arc<Config>) -> anyhow::Result<()> {
    let checks = doctor::run_checks(&cfg).await;
    let caps = doctor::caps(&cfg, &checks);
    for c in &checks {
        if c.ok {
            tracing::info!(check = c.name, detail = %c.detail, "host capability");
        } else {
            tracing::warn!(check = c.name, detail = %c.detail, "host capability missing");
        }
    }
    if caps.tiers().is_empty() {
        anyhow::bail!("no tier available on this host; run `qafas doctor`");
    }
    tracing::info!(tiers = ?caps.tiers(), "serving");

    let bus = events::bus();

    // TLS material first: the fingerprint goes into /healthz, the create reply and
    // the host registration, so every client can pin without a side channel — and
    // the egress proxy started below pins this same certificate for its event sink.
    let tls = if cfg.tls {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|_| anyhow::anyhow!("a rustls crypto provider is already installed"))?;
        Some(tls::load_or_generate(&cfg)?)
    } else {
        None
    };

    // The persisted sandbox table, read before anything sweeps: it is the only
    // thing that says which jail, archive and /30 slot still has an owner.
    // `stopped`/`archived` microVMs whose files are there come back; everything
    // else in the table died with the previous process.
    let (adopt, gone) = {
        let records = livetable::load_all(&cfg);
        match caps.remote {
            true => livetable::plan(&cfg, records, |p| p.exists()),
            false => (Vec::new(), records),
        }
    };

    // The pooled backend: one of them, chosen by which container/VM tier the
    // host serves. `caps` already made them exclusive (D25: remote wins over vm),
    // so this is a lookup, not a preference. The native tier has no pool.
    let pooled: Arc<dyn backend::Backend> = if caps.vm {
        let p = backend::podman::Podman::new(cfg.clone())?;
        // Idempotent: the internal network plus the egress proxy container.
        p.ensure_infra().await?;
        Arc::new(p)
    } else {
        #[cfg(target_os = "linux")]
        {
            if caps.remote {
                Arc::new(backend::firecracker::Firecracker::new(cfg.clone(), &adopt)?)
            } else {
                Arc::new(backend::Unavailable)
            }
        }
        #[cfg(not(target_os = "linux"))]
        Arc::new(backend::Unavailable)
    };

    let policy =
        pool::Policy { base: cfg.pool_size, recent_secs: cfg.pool_recent_secs, recent_max: cfg.pool_recent_max };
    let pool = pool::Pool::new(pooled.clone(), policy, bus.clone(), cfg.host_id.clone(), cfg.default_limits());
    let mut state = api::AppState::new(cfg.clone(), pool, bus.clone(), caps);
    // A build the previous run was killed in the middle of left a work tree and
    // an export container behind; neither has an owner now.
    snapshots::sweep_builds(&cfg);
    state.pool.load_warm(state.snapshots.warm_targets().await).await;
    state.tls_fingerprint = tls.as_ref().map(|t| t.fingerprint.clone()).unwrap_or_default();
    state.host_caps = doctor::host_caps(&checks);

    if caps.native {
        // Anything a previous run left behind is killed before we start, so a
        // crashed daemon cannot leak a process group into the next session.
        let n = backend::native::sweep_leftovers(&cfg.scratch_dir);
        if n > 0 {
            tracing::warn!(groups = n, "killed process groups left by a previous run");
        }
        let native = Arc::new(backend::native::Native::new(cfg.clone(), bus.clone())?);
        sblog::spawn(native.reg.clone());
        state.native = Some(native);
    }

    state.metrics.spawn(bus.clone());
    events::spawn_egress_rules(bus.clone(), cfg.host_id.clone());
    api::spawn_reaper(state.clone());

    // A microVM pool is not tied to a workspace, so it can be warm before the
    // first request — but v4 captures `base`'s memory first, so the pool fills
    // with restores rather than with boots.
    if !pooled.pool_by_workspace() {
        let st = state.clone();
        tokio::spawn(async move {
            snapshots::ensure_base_memory(&st).await;
            scan::ensure_base(&st).await;
            let dir = st.snapshots.dir_of(snapshots::BASE);
            let snap = crate::snapshots::has_memory(&dir).then_some(backend::SnapshotRef { dir });
            st.pool.spawn_refill(snapshots::BASE.into(), String::new(), String::new(), snap);
        });
    }
    // v5.2: a container pool fills per workspace, so nothing waits on this scan.
    if pooled.name() == "podman" {
        let st = state.clone();
        tokio::spawn(async move { scan::ensure_base(&st).await });
    }

    let http = events::http_client_with(tls::client_config(&cfg.ca_file)?);
    events::spawn_flusher(cfg.clone(), bus.clone(), http.clone(), state.metrics.clone());

    // Startup reconciliation of the persisted table, after the flusher so the
    // events reach the control plane and before the registrar so the first
    // heartbeat already lists what came back.
    //
    // A record with nothing behind it any more: the sweep has taken its files,
    // so say why it is gone rather than leaving the control plane to infer it
    // from the next heartbeat's silence.
    for rec in &gone {
        state.forget(&rec.id);
        state.emit(
            &rec.id,
            &events::Corr::default(),
            proto::EventType::SandboxDestroyed,
            serde_json::json!({"reason": "daemon_restart"}),
        );
    }
    let (mut stopped, mut archived) = (0, 0);
    for rec in &adopt {
        if !state.adopt(rec, pooled.clone()).await {
            state.forget(&rec.id);
            continue;
        }
        match rec.state {
            proto::SandboxState::Archived => archived += 1,
            _ => stopped += 1,
        }
    }
    if stopped + archived > 0 {
        tracing::info!(stopped, archived, "re-adopted {stopped} stopped and {archived} archived sandboxes");
    }

    // v4d: the ones the previous shutdown stopped only because it was going down
    // come back running, before the registrar so the first heartbeat already
    // says `ready`. Concurrent, and bounded by the backend's own restore waits.
    // (An id whose adoption failed above is simply not live, which `resume_parked` skips.)
    let parked: Vec<String> = adopt.iter().filter(|r| r.resume_on_start).map(|r| r.id.clone()).collect();
    if !parked.is_empty() {
        let n = api::resume_parked(&state, &parked).await;
        tracing::info!(resumed = n, "resumed {n} parked sandboxes");
    }

    events::spawn_registrar(cfg.clone(), http, state.clone());

    // The Firecracker backend has no proxy container to run for it.
    #[cfg(target_os = "linux")]
    if caps.remote && !caps.vm {
        let (policy, token, host_id) = (cfg.policy.clone(), cfg.token.clone(), cfg.host_id.clone());
        let sink = format!("{}://127.0.0.1:{}/internal/events", cfg.scheme(), cfg.listen.port());
        let sink_ca = tls.as_ref().map(|t| t.cert_pem.clone());
        tokio::spawn(async move {
            let listen = SocketAddr::from(([0, 0, 0, 0], proto::EGRESS_PROXY_PORT));
            if let Err(e) = proxy::run(listen, &policy, Some(sink), sink_ca, token, host_id).await {
                tracing::error!(error = %e, "in-process egress proxy died");
            }
        });
    }

    tracing::info!(
        listen = %cfg.listen, host_id = %cfg.host_id, url = %cfg.public_base(),
        tls = cfg.tls, "qafas listening",
    );
    let app = api::router(state.clone());
    match tls {
        Some(t) => {
            let rustls_cfg = axum_server::tls_rustls::RustlsConfig::from_pem(t.cert_pem, t.key_pem).await?;
            let handle = axum_server::Handle::new();
            tokio::spawn({
                let (handle, state) = (handle.clone(), state.clone());
                async move {
                    terminate().await;
                    tracing::info!("shutting down; parking or destroying sandboxes");
                    api::shutdown(&state).await;
                    // The flusher posts once a second: give the park/destroy
                    // events one tick to reach the control plane before exit.
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    handle.graceful_shutdown(Some(std::time::Duration::from_secs(2)));
                }
            });
            // With connect info: `/metrics` is open to a loopback peer only (§3 v4).
            axum_server::bind_rustls(cfg.listen, rustls_cfg)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async move {
                    terminate().await;
                    tracing::info!("shutting down; parking or destroying sandboxes");
                    api::shutdown(&state).await;
                    // The flusher posts once a second: give the park/destroy
                    // events one tick to reach the control plane before exit.
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                })
                .await?;
        }
    }
    Ok(())
}

/// SIGTERM matters as much as SIGINT: it is how launchd and systemd stop us, and
/// an unhandled one orphans every container and process group we own.
async fn terminate() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
