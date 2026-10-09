//! Local backend: containers inside the already-running podman machine (D3),
//! driven over the libpod REST socket — or, v0.8, over a Docker Engine socket
//! (D32), the same calls in Docker's dialect. The CLI is never on the hot path.
//! ponytail: one backend named "podman" for both runtimes, because callers key
//! on the name for the image model they share; split it if the two ever differ
//! in more than request shapes.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector};
use serde_json::{json, Value};

use super::{Backend, BoxFut, Connector, Sandbox, Spec};
use crate::config::Config;
use crate::events::now_rfc3339;

const API: &str = "/v5.0.0/libpod";
pub const NETWORK: &str = "sbx-internal";
pub const PROXY_CONTAINER: &str = "sbx-proxy";

pub struct Podman {
    sock: String,
    http: Client<UnixConnector, Full<Bytes>>,
    cfg: Arc<Config>,
    /// The socket is a Docker Engine, not podman: set once by `ensure_infra`.
    docker: std::sync::atomic::AtomicBool,
    /// The proxy container's address on the internal network, filled in by
    /// `ensure_infra` before any sandbox is created.
    proxy_ip: std::sync::Mutex<String>,
    /// The proxy's relay listener as the host sees it, when the host has no
    /// route onto the sandbox network (rootful podman on Linux). `None`: dial
    /// the published loopback port, which gvproxy makes work on macOS.
    relay: std::sync::Mutex<Option<SocketAddr>>,
    /// Container name → current address on the sandbox network, for `Relay`.
    table: super::RelayTable,
}

/// Where the proxy container listens for the host's relay CONNECTs.
const RELAY_PORT: u16 = 3129;

/// `SBX_RUNTIME_SOCK` (or its older name `SBX_PODMAN_SOCK`), else the socket a
/// Linux host's `podman.socket` unit provides (the user's own first, then the
/// system one — root's is not connectable by anyone else), else Docker's, else
/// ask the podman machine once at startup (macOS).
pub fn discover_socket() -> anyhow::Result<String> {
    for var in ["SBX_RUNTIME_SOCK", "SBX_PODMAN_SOCK"] {
        if let Some(s) = std::env::var(var).ok().filter(|s| !s.is_empty()) {
            return Ok(s);
        }
    }
    let mut local =
        std::env::var("XDG_RUNTIME_DIR").map(|d| vec![format!("{d}/podman/podman.sock")]).unwrap_or_default();
    local.push("/run/podman/podman.sock".into());
    local.push("/var/run/docker.sock".into());
    if let Some(s) = local.into_iter().find(|p| std::path::Path::new(p).exists()) {
        return Ok(s);
    }
    let out = std::process::Command::new("podman")
        .args(["machine", "inspect", "--format", "{{.ConnectionInfo.PodmanSocket.Path}}"])
        .output();
    let path = out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    if path.is_empty() {
        anyhow::bail!("cannot find a podman or Docker socket; set SBX_RUNTIME_SOCK");
    }
    Ok(path)
}

impl Podman {
    pub fn new(cfg: Arc<Config>) -> anyhow::Result<Self> {
        Ok(Self {
            sock: discover_socket()?,
            http: Client::unix(),
            cfg,
            docker: Default::default(),
            proxy_ip: std::sync::Mutex::new(String::new()),
            relay: std::sync::Mutex::new(None),
            table: Default::default(),
        })
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> anyhow::Result<(u16, Bytes)> {
        let uri: hyper::Uri = hyperlocal::Uri::new(&self.sock, path).into();
        let payload = body.map(|v| serde_json::to_vec(&v)).transpose()?.unwrap_or_default();
        let req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(payload)))?;
        let resp = self.http.request(req).await?;
        let status = resp.status().as_u16();
        let bytes = resp.into_body().collect().await?.to_bytes();
        Ok((status, bytes))
    }

    async fn json(&self, method: &str, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
        let (status, bytes) = self.call(method, path, body).await?;
        if !(200..300).contains(&status) {
            anyhow::bail!("podman {method} {path} -> {status}: {}", String::from_utf8_lossy(&bytes));
        }
        Ok(serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn is_docker(&self) -> bool {
        self.docker.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// This runtime's API root: libpod's, or Docker's unversioned one.
    fn api(&self) -> &'static str {
        if self.is_docker() {
            ""
        } else {
            API
        }
    }

    /// podman answers `/_ping` with a `Libpod-Api-Version` header; Docker does not.
    async fn detect(&self) -> anyhow::Result<()> {
        let uri: hyper::Uri = hyperlocal::Uri::new(&self.sock, "/_ping").into();
        let resp = self.http.request(hyper::Request::get(uri).body(Full::new(Bytes::new()))?).await?;
        let docker = !resp.headers().contains_key("libpod-api-version");
        self.docker.store(docker, std::sync::atomic::Ordering::Relaxed);
        if docker {
            let version = self.json("GET", "/version", None).await?["Version"].as_str().unwrap_or("").to_string();
            docker_supported(&version)?;
            tracing::info!(%version, sock = %self.sock, "container runtime: Docker Engine");
        }
        Ok(())
    }

    /// Force-removes sandbox containers left behind by a previous run (a crash,
    /// or a signal we did not handle). Never touches the proxy, which
    /// `ensure_proxy` recreates on its own.
    async fn sweep_orphans(&self) -> anyhow::Result<()> {
        let api = self.api();
        let list = self.json("GET", &format!("{api}/containers/json?all=true"), None).await?;
        for name in list
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .flat_map(|c| c["Names"].as_array().cloned().unwrap_or_default())
            // Docker lists names as "/name".
            .filter_map(|n| n.as_str().map(|n| n.trim_start_matches('/').to_string()))
            .filter(|n| is_sandbox_container(n))
        {
            let _ = self.call("DELETE", &format!("{api}/containers/{name}?force=true&v=true&timeout=0"), None).await;
            tracing::info!(container = %name, "removed orphaned sandbox from a previous run");
        }
        Ok(())
    }
}

/// Only containers this daemon created (`sbx-sbx_<id>`). A bare `sbx-` prefix also
/// matched `deploy/monitoring`'s `sbx-prometheus`/`sbx-grafana`… and deleted them on
/// every restart (2026-09-15).
fn is_sandbox_container(name: &str) -> bool {
    name.strip_prefix("sbx-").is_some_and(|rest| rest.starts_with("sbx_"))
}

#[cfg(test)]
mod sweep_tests {
    #[test]
    fn only_our_containers_are_orphans() {
        assert!(super::is_sandbox_container("sbx-sbx_jwerqhfe"));
        for other in ["sbx-proxy", "sbx-prometheus", "sbx-grafana", "sbxd", "postgres", "sbx_jwerqhfe"] {
            assert!(!super::is_sandbox_container(other), "{other}");
        }
    }
}

impl Podman {
    /// The guest image, pulled once on a host that has never seen it (a fresh
    /// install, a new release). An air-gapped host `podman load`s the release
    /// tarball instead and this finds it present. The libpod create call does
    /// not pull for us. ponytail: only the default image; every tool in
    /// images/templates.json resolves to it today — pull each distinct one when
    /// that stops being true.
    async fn ensure_image(&self) -> anyhow::Result<()> {
        let image = &self.cfg.template_image;
        let (exists, pull) = match self.is_docker() {
            true => (format!("/images/{image}/json"), format!("/images/create?fromImage={image}")),
            false => (format!("{API}/images/{image}/exists"), format!("{API}/images/pull?reference={image}")),
        };
        let (status, _) = self.call("GET", &exists, None).await?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        tracing::info!(image, "guest image not present; pulling");
        let (status, body) = self.call("POST", &pull, None).await?;
        let body = String::from_utf8_lossy(&body);
        // The pull streams JSON lines and answers 200 even when it fails; the
        // failure is a line with `error` in it.
        let error = body
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find_map(|v| v["error"].as_str().map(String::from));
        if !(200..300).contains(&status) || error.is_some() {
            anyhow::bail!(
                "pull {image}: {status} {}",
                error.unwrap_or_else(|| body.lines().last().unwrap_or_default().into())
            );
        }
        tracing::info!(image, "guest image pulled");
        Ok(())
    }

    /// Idempotent boot steps: the guest image, the internal network and the egress proxy.
    pub async fn ensure_infra(&self) -> anyhow::Result<()> {
        self.detect().await?;
        self.sweep_orphans().await?;
        self.ensure_image().await?;
        let subnet = match self.is_docker() {
            true => self.docker_network().await?,
            false => self.libpod_network().await?,
        };
        let static_ip = subnet.as_deref().and_then(proxy_ip_for);
        if static_ip.is_none() {
            tracing::warn!(?subnet, "no usable subnet on {NETWORK}; the proxy takes a dynamic address");
        }
        self.ensure_proxy(static_ip.as_deref(), subnet.as_deref()).await
    }

    /// Docker cannot turn its embedded resolver off; on an `internal` network it
    /// answers only the network's own container names and, since 26.0, forwards
    /// nothing (D32, security.md M45).
    async fn docker_network(&self) -> anyhow::Result<Option<String>> {
        let (status, _) = self.call("GET", &format!("/networks/{NETWORK}"), None).await?;
        if status == 404 {
            let (s, b) = self
                .call("POST", "/networks/create", Some(json!({"Name": NETWORK, "Internal": true, "Driver": "bridge"})))
                .await?;
            if !(200..300).contains(&s) && s != 409 {
                anyhow::bail!("create network: {s} {}", String::from_utf8_lossy(&b));
            }
        }
        let net = self.json("GET", &format!("/networks/{NETWORK}"), None).await?;
        Ok(net["IPAM"]["Config"][0]["Subnet"].as_str().map(str::to_string))
    }

    async fn libpod_network(&self) -> anyhow::Result<Option<String>> {
        // No DNS on the sandbox network: the sandbox must not have a resolver of
        // its own (D7). It reaches the proxy by IP, which is why we read the
        // proxy's address back below.
        let (status, _) = self.call("GET", &format!("{API}/networks/{NETWORK}/exists"), None).await?;
        if status == 204 {
            let net = self.json("GET", &format!("{API}/networks/{NETWORK}/json"), None).await?;
            if net["dns_enabled"] == true {
                tracing::info!("recreating {NETWORK} without DNS");
                let _ =
                    self.call("DELETE", &format!("{API}/containers/{PROXY_CONTAINER}?force=true&v=true"), None).await;
                let (s, b) = self.call("DELETE", &format!("{API}/networks/{NETWORK}?force=true"), None).await?;
                if !(200..300).contains(&s) {
                    anyhow::bail!("cannot replace the {NETWORK} network: {s} {}", String::from_utf8_lossy(&b));
                }
            }
        }
        let (status, body) = self
            .call(
                "POST",
                &format!("{API}/networks/create"),
                Some(json!({"name": NETWORK, "internal": true, "dns_enabled": false})),
            )
            .await?;
        // 409 = already there, which is the normal case after the first run.
        if !(200..300).contains(&status) && status != 409 {
            anyhow::bail!("create network: {status} {}", String::from_utf8_lossy(&body));
        }
        // Read the subnet back rather than dictating one: the network may be an
        // existing one this daemon did not create.
        let net = self.json("GET", &format!("{API}/networks/{NETWORK}/json"), None).await?;
        Ok(net["subnets"][0]["subnet"].as_str().map(str::to_string))
    }

    /// Always recreated, so the proxy always has the current `policy/egress.json`
    /// and the current sink port. It holds no state worth keeping.
    async fn ensure_proxy(&self, static_ip: Option<&str>, subnet: Option<&str>) -> anyhow::Result<()> {
        let api = self.api();
        let _ = self.call("DELETE", &format!("{api}/containers/{PROXY_CONTAINER}?force=true&v=true"), None).await;
        // The policy travels as content, not as a bind mount of the host path:
        // when qafas itself runs in a container the path means nothing to podman.
        let policy = std::fs::read_to_string(&self.cfg.policy).unwrap_or_else(|e| {
            tracing::warn!(path = %self.cfg.policy, error = %e, "no egress policy readable; the proxy denies everything");
            String::new()
        });
        let sink =
            format!("{}://host.containers.internal:{}/internal/events", self.cfg.scheme(), self.cfg.listen.port());
        // With a TLS API the sink is https too, and the proxy pins this daemon's own
        // certificate: no SAN lists host.containers.internal.
        let sink_ca = match self.cfg.tls {
            true => std::fs::read_to_string(crate::tls::cert_path(&self.cfg))?,
            false => String::new(),
        };
        let mut command = vec!["proxy".to_string(), "--sink".into(), sink];
        if let Some(net) = subnet {
            command.extend(["--relay".into(), format!("0.0.0.0:{RELAY_PORT}"), "--relay-net".into(), net.into()]);
        }
        let env = json!({
            "SBX_POLICY_JSON": policy,
            "SBX_SINK_CA": sink_ca,
            "SBX_TOKEN": self.cfg.token,
            "SBX_HOST_ID": self.cfg.host_id,
            "RUST_LOG": std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        });
        // The image ENTRYPOINT is guest-agent, so the proxy has to override it.
        let entrypoint = ["/usr/local/bin/qafas"];
        if self.is_docker() {
            let mut hc = json!({
                "NetworkMode": "bridge",
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "AutoRemove": true,
                // podman's name for the host, so the sink URL is one string on both.
                "ExtraHosts": ["host.containers.internal:host-gateway"],
            });
            if !self.cfg.proxy_dns.is_empty() {
                hc["Dns"] = json!(self.cfg.proxy_dns);
            }
            let spec = json!({"Image": self.cfg.template_image, "Entrypoint": entrypoint, "Cmd": command,
                              "Env": env_list(&env), "HostConfig": hc});
            self.json("POST", &format!("/containers/create?name={PROXY_CONTAINER}"), Some(spec)).await?;
            // Dual-homed on purpose: the sandbox network has no other exit (D7).
            let ep = static_ip.map_or(json!({}), |ip| json!({"IPAMConfig": {"IPv4Address": ip}}));
            let join = json!({"Container": PROXY_CONTAINER, "EndpointConfig": ep});
            self.json("POST", &format!("/networks/{NETWORK}/connect"), Some(join)).await?;
        } else {
            let mut spec = json!({
                "name": PROXY_CONTAINER,
                "image": self.cfg.template_image,
                "entrypoint": entrypoint,
                "command": command,
                "netns": {"nsmode": "bridge"},
                // Dual-homed on purpose: the sandbox network has no other exit (D7).
                "Networks": {"podman": {}, NETWORK: match static_ip {
                    Some(ip) => json!({"static_ips": [ip]}),
                    None => json!({}),
                }},
                "env": env,
                "no_new_privileges": true,
                "cap_drop": ["ALL"],
                "remove": true,
            });
            if !self.cfg.proxy_dns.is_empty() {
                spec["dns_server"] = json!(self.cfg.proxy_dns);
            }
            self.json("POST", &format!("{API}/containers/create"), Some(spec)).await?;
        }
        self.json("POST", &format!("{api}/containers/{PROXY_CONTAINER}/start"), None).await?;
        let st = self.json("GET", &format!("{api}/containers/{PROXY_CONTAINER}/json"), None).await?;
        self.record_proxy_ip(&st)?;
        tracing::info!(proxy = %self.proxy_ip.lock().unwrap(), "egress proxy container up");
        self.probe_relay(&st).await;
        Ok(())
    }

    /// Linux only: if the host can reach the proxy on the runtime's default
    /// network, guest agents are reached through its relay — under rootful podman
    /// the sandbox network (`internal`) has no host route, and Docker publishes no
    /// port for a container on an internal network, so a published port on
    /// 127.0.0.1 leads nowhere. Everywhere else the published port is the way.
    async fn probe_relay(&self, inspect: &Value) {
        *self.relay.lock().unwrap() = None;
        if !cfg!(target_os = "linux") {
            return;
        }
        let default_net = if self.is_docker() { "bridge" } else { "podman" };
        let ip = inspect["NetworkSettings"]["Networks"][default_net]["IPAddress"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok());
        let Some(ip) = ip else { return };
        let via = SocketAddr::new(ip, RELAY_PORT);
        for _ in 0..6 {
            let dial = tokio::time::timeout(Duration::from_millis(500), tokio::net::TcpStream::connect(via)).await;
            if dial.is_ok_and(|r| r.is_ok()) {
                tracing::info!(%via, "guest agents reached through the proxy relay");
                *self.relay.lock().unwrap() = Some(via);
                return;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        tracing::info!("guest agents reached on published loopback ports");
    }

    /// The address podman actually gave it, which `proxy_ip_for` asked for and
    /// this confirms — the env every sandbox gets is built from this value, not
    /// from the request.
    fn record_proxy_ip(&self, inspect: &Value) -> anyhow::Result<()> {
        let ip = inspect["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("egress proxy has no address on {NETWORK}"))?;
        *self.proxy_ip.lock().unwrap() = ip.to_string();
        Ok(())
    }

    /// The published guest-agent port, from an inspect body.
    fn published_port(info: &Value) -> Option<u16> {
        info["NetworkSettings"]["Ports"][format!("{}/tcp", proto::GUEST_AGENT_PORT)][0]["HostPort"]
            .as_str()
            .and_then(|s| s.parse().ok())
    }

    /// The sandbox's environment, the same on both runtimes.
    fn sandbox_env(&self, spec: &Spec, agent_token: &str) -> Value {
        // By address, not by name: the sandbox network has no resolver (D7).
        let proxy = format!("http://{}:{}", self.proxy_ip.lock().unwrap(), proto::EGRESS_PROXY_PORT);
        json!({
            "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
            "http_proxy": proxy, "https_proxy": proxy,
            "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
            "SBX_ID": spec.id,
            "SBX_HOST_HOME": std::env::var("HOME").unwrap_or_default(),
            "SBX_HOST_ID": self.cfg.host_id,
            "SBX_CHROME_NO_SANDBOX": "1",
            "HOME": "/home/agent",
            // The in-guest rule set needs to know which directory is the
            // workspace; without it every path looks like an escape.
            "SBX_WORKSPACE": spec.workspace_path,
            "SBX_MAX_UPLOAD_MB": self.cfg.max_upload_mb.to_string(),
            // The published port is on the host's loopback, so reachability
            // is not the boundary here: this secret is (protocol §2). It
            // lives in the container environment, so it survives stop/start,
            // and it is in `PROTECTED_ENV`, so no exec can read or set it.
            "SBX_AGENT_TOKEN": agent_token,
        })
    }

    fn spec(&self, spec: &Spec, host_port: u16, agent_token: &str) -> Value {
        match self.is_docker() {
            true => self.docker_spec(spec, agent_token),
            false => self.libpod_spec(spec, host_port, agent_token),
        }
    }

    /// The same container in Docker's dialect. Docker has no idmapped bind
    /// mounts and no `keep-id`, so a workspace stays writable by running the
    /// sandbox as its owner (never root: `refuse_workspace` turns a root-owned
    /// one away first). No port is published: Docker publishes none on an
    /// internal network, so qafas reaches the agent through the proxy relay.
    fn docker_spec(&self, spec: &Spec, agent_token: &str) -> Value {
        let image = if spec.image.is_empty() { &self.cfg.template_image } else { &spec.image };
        let tmp_mib = self.cfg.max_size_disk_mib().max(spec.limits.disk_mib);
        let w = spec.workspace_path.as_str();
        let (user, mounts) = match w {
            "/home/agent" => ("1000:1000".to_string(), json!([])),
            _ => {
                let user = workspace_owner(w)
                    .filter(|(uid, _)| *uid != 0)
                    .map_or("1000:1000".to_string(), |(u, g)| format!("{u}:{g}"));
                (user, json!([{"Type": "bind", "Source": w, "Target": w}]))
            }
        };
        let mut security = vec!["no-new-privileges"];
        if selinux_enforcing() {
            security.push("label=disable"); // the same trade as the libpod spec below
        }
        let mut hc = json!({
            "NetworkMode": NETWORK,
            "Mounts": mounts,
            "Tmpfs": {
                "/tmp": format!("rw,nosuid,nodev,size={tmp_mib}m"),
                "/home/agent": "rw,nosuid,nodev,size=512m,mode=1777",
            },
            "ReadonlyRootfs": true,
            "CapDrop": ["ALL"],
            "SecurityOpt": security,
        });
        if let (Some(hc), Value::Object(limits)) = (hc.as_object_mut(), docker_limits(&spec.limits)) {
            hc.extend(limits);
        }
        json!({
            "Image": image,
            "User": user,
            "WorkingDir": w,
            "Env": env_list(&self.sandbox_env(spec, agent_token)),
            "HostConfig": hc,
        })
    }

    fn libpod_spec(&self, spec: &Spec, host_port: u16, agent_token: &str) -> Value {
        let name = format!("sbx-{}", spec.id);
        let image = if spec.image.is_empty() { &self.cfg.template_image } else { &spec.image };
        // v5 §3a: the scratch tmpfs is sized once, at the largest configured
        // size, because the uid-1000 agent cannot remount it when a pooled
        // container is handed out. The memory cgroup — which `apply_limits`
        // does move — is what bounds what actually lands in it.
        // design: so a pooled `micro` can see a 4 GiB /tmp and is stopped by its 512 MiB memory cgroup, not by ENOSPC; per-size warm pools are the upgrade.
        let tmp_mib = self.cfg.max_size_disk_mib().max(spec.limits.disk_mib);
        let mut mounts = vec![
            json!({"destination": "/tmp", "source": "tmpfs", "type": "tmpfs",
                   "options": ["nosuid", "nodev", format!("size={tmp_mib}m")]}),
            json!({"destination": "/home/agent", "source": "tmpfs", "type": "tmpfs", // design: `uid=` on a tmpfs lands in the wrong user namespace under
            // rootless podman (host 100000). The container has one user, so a
            // world-writable HOME is equivalent; guest-agent plants the canaries.
            "options": ["nosuid", "nodev", "size=512m", "mode=1777"]}),
        ];
        if spec.workspace_path != "/home/agent" {
            // Same absolute path inside and out; the machine already shares
            // /Users, /private and /var/folders over virtiofs (D4).
            let mut options = vec!["rw".to_string(), "rbind".into()];
            options.extend(workspace_idmap(&spec.workspace_path));
            mounts.push(json!({
                "destination": spec.workspace_path, "source": spec.workspace_path,
                "type": "bind", "options": options
            }));
        }
        let mut c = json!({
            "name": name,
            "image": image,
            "user": "1000:1000",
            "netns": {"nsmode": "bridge"},
            "Networks": {NETWORK: {}},
            "portmappings": [{"container_port": proto::GUEST_AGENT_PORT, "host_port": host_port,
                              "host_ip": "127.0.0.1", "protocol": "tcp"}],
            "work_dir": spec.workspace_path,
            "env": self.sandbox_env(spec, agent_token),
            "mounts": mounts,
            "read_only_filesystem": true,
            // No container-wide no_new_privileges (D33): under crun's AppArmor profile
            // (Ubuntu 24.04) it stacks the container's label, and the profile then refuses
            // every signal between the sandbox's own processes — the `timeout_ms` killpg,
            // `kill`, `timeout` all fail with EACCES. The guest agent sets PR_SET_NO_NEW_PRIVS
            // on every process it starts (`harden::apply`), so the workload still has it.
            "cap_drop": ["ALL"],
            "resource_limits": resource_limits(&spec.limits),
            // v4: NOT `remove: true`. An autoremove container is deleted the
            // moment it stops, and §3a's `stop` has to keep the filesystem.
            // `destroy` deletes explicitly, and `sweep_orphans` clears whatever
            // a crashed daemon left behind on the next boot.
        });
        if !rootful() {
            // Rootless (the podman machine, a developer's Linux box): keep-id maps the
            // invoking host uid onto 1000, so bind-mounted workspace files stay
            // writable (PLAN §11 row 2). Rootful, the same request is a no-op on one
            // podman and a real user namespace on another — where sysfs and mqueue
            // then refuse to mount under nesting — so the workspace gets an idmapped
            // mount instead (`workspace_idmap`).
            c["userns"] = json!({"nsmode": "keep-id", "value": "uid=1000,gid=1000"});
        }
        if selinux_enforcing() {
            // ponytail: unconfined by SELinux rather than relabelling the workspace —
            // `:z` rewrites the host tree's labels for good (a web root served by httpd
            // stops working). The boundary is the namespaces, seccomp, the capability
            // set and the network; a container_t policy that admits the workspace is
            // the upgrade path (docs/security.md).
            c["selinux_opts"] = json!(["disable"]);
        }
        c
    }
}

fn selinux_enforcing() -> bool {
    std::fs::read_to_string("/sys/fs/selinux/enforce").map(|s| s.trim() == "1").unwrap_or(false)
}

/// Root talking to a system podman on Linux — a service. The podman machine's
/// connection on macOS is rootless, whoever runs the daemon.
fn rootful() -> bool {
    cfg!(target_os = "linux") && nix::unistd::Uid::effective().is_root()
}

/// v5 §3a. The OCI `LinuxResources` block, which libpod takes both in a create
/// spec and as the whole body of `POST /containers/{name}/update` (verified
/// against podman 5.6.2: the values land in the container's cgroup live).
/// `cpu.max` is `cpus × 100000` per a 100000 µs period.
fn resource_limits(l: &proto::SandboxLimits) -> Value {
    json!({
        "memory": {"limit": l.mem_mib * 1024 * 1024},
        "cpu": {"quota": (l.cpus * 100_000.0).round() as i64, "period": 100_000},
        "pids": {"limit": i64::from(l.pids)},
    })
}

/// v5 §3a in Docker's words: the same cgroup values as `resource_limits`, as
/// both a create's `HostConfig` fields and the whole `update` body. Swap equal
/// to memory: no swap, as on libpod.
fn docker_limits(l: &proto::SandboxLimits) -> Value {
    let mem = l.mem_mib * 1024 * 1024;
    json!({
        "Memory": mem,
        "MemorySwap": mem,
        "CpuQuota": (l.cpus * 100_000.0).round() as i64,
        "CpuPeriod": 100_000,
        "PidsLimit": i64::from(l.pids),
    })
}

/// `{"K": "V"}` → `["K=V"]`, Docker's environment shape.
fn env_list(env: &Value) -> Vec<String> {
    env.as_object()
        .map(|m| m.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default())).collect())
        .unwrap_or_default()
}

/// Docker before 26.0 forwarded DNS from an `internal` network to the host's
/// resolver (CVE-2024-29018), which would hand a sandbox a working resolver.
fn docker_supported(version: &str) -> anyhow::Result<()> {
    let major: u32 = version.split('.').next().and_then(|m| m.parse().ok()).unwrap_or(0);
    anyhow::ensure!(
        major >= 26,
        "Docker Engine {version:?} is too old for the vm tier: it needs 26.0 or later, whose \
         internal networks stop forwarding DNS (CVE-2024-29018)"
    );
    Ok(())
}

/// Who owns the workspace directory, creating it first (the runtime would, as
/// root, anyway) so there is an owner to read.
#[cfg(unix)]
fn workspace_owner(path: &str) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let _ = std::fs::create_dir_all(path);
    let m = std::fs::metadata(path).ok()?;
    Some((m.uid(), m.gid()))
}

/// The address the egress proxy always gets on `sbx-internal`: the last usable
/// one in the subnet. Sandboxes bake the proxy's address into their environment
/// at create time, so it must survive the proxy container being recreated —
/// which `ensure_infra` does on every daemon start. The last address is the safe
/// one to pin: podman's host-local IPAM hands out the low end of the range, so
/// nothing else is ever given it. `None` for a subnet with no room (or IPv6),
/// which puts the proxy back on a dynamic address.
/// Rootful podman on Linux runs the container's uid 1000 as the host's uid 1000
/// (`keep-id` is a no-op there), so a workspace owned by anyone else would be
/// read-only or unreachable. An idmapped mount shows its owner as uid 1000 inside
/// and lands the sandbox's writes as that owner — what the bind mount under the
/// podman machine gives on macOS. A missing directory is created first (podman
/// would, as root, anyway) so there is an owner to map.
#[cfg(target_os = "linux")]
fn workspace_idmap(path: &str) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    if !rootful() {
        return None;
    }
    let _ = std::fs::create_dir_all(path);
    let m = std::fs::metadata(path).ok()?;
    Some(format!("idmap=uids={}-1000-1;gids={}-1000-1", m.uid(), m.gid()))
}

#[cfg(not(target_os = "linux"))]
fn workspace_idmap(_path: &str) -> Option<String> {
    None
}

fn proxy_ip_for(subnet: &str) -> Option<String> {
    let (net, len) = subnet.split_once('/')?;
    let (net, len) = (net.parse::<std::net::Ipv4Addr>().ok()?, len.parse::<u32>().ok()?);
    if len > 30 {
        return None;
    }
    let base = u32::from(net) & !(u32::MAX >> len);
    Some(std::net::Ipv4Addr::from((base | (u32::MAX >> len)) - 1).to_string())
}

/// A free loopback port and the listener holding it. podman picks no port of
/// its own here: with `host_port: 0` the mapping is re-decided on every start
/// and a woken sandbox would move while clients still hold the old endpoint.
/// The reservation is dropped immediately before the create call, which is as
/// small as the window gets — podman has to do its own bind. A collision there
/// surfaces as a create error, never as a wrong sandbox.
fn reserve_port() -> anyhow::Result<(u16, std::net::TcpListener)> {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok((l.local_addr()?.port(), l))
}

impl Backend for Podman {
    fn name(&self) -> &'static str {
        "podman"
    }

    fn refuse_workspace(&self, path: &str) -> Option<String> {
        if !self.is_docker() || path == "/home/agent" {
            return None;
        }
        // Read only: a directory created here would be root's, and refused anyway.
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(path).map(|m| m.uid()) {
            Ok(0) => Some(format!(
                "{path} is owned by root; on the Docker runtime a sandbox runs as its workspace's owner, \
                 never as root — use a directory owned by a regular user, or podman"
            )),
            Err(_) => Some(format!(
                "{path} does not exist; on the Docker runtime create it first, as the user who will work in it"
            )),
            _ => None,
        }
    }

    fn create(&self, spec: Spec) -> BoxFut<'_, anyhow::Result<Sandbox>> {
        Box::pin(async move {
            let started = Instant::now();
            let name = format!("sbx-{}", spec.id);
            let created_at = now_rfc3339();
            let (host_port, reserved) = reserve_port()?;
            let agent_token = super::mint_agent_token()?;
            let body = self.spec(&spec, host_port, &agent_token);
            // podman binds it next, and nothing of ours runs in between.
            drop(reserved);
            let api = self.api();
            match self.is_docker() {
                true => self.json("POST", &format!("/containers/create?name={name}"), Some(body)).await?,
                false => self.json("POST", &format!("{API}/containers/create"), Some(body)).await?,
            };
            self.json("POST", &format!("{api}/containers/{name}/start"), None).await?;

            let info = self.json("GET", &format!("{api}/containers/{name}/json"), None).await?;
            let port = Self::published_port(&info);
            let peer_ip: Option<IpAddr> =
                info["NetworkSettings"]["Networks"][NETWORK]["IPAddress"].as_str().and_then(|s| s.parse().ok());

            let relay = *self.relay.lock().unwrap();
            let connector = match (relay, peer_ip) {
                (Some(via), Some(ip)) => {
                    self.table.lock().unwrap().insert(name.clone(), ip);
                    Connector::Relay {
                        via,
                        name: name.clone(),
                        port: proto::GUEST_AGENT_PORT,
                        table: self.table.clone(),
                    }
                }
                _ => {
                    let port = port.ok_or_else(|| anyhow::anyhow!("no published port for {name}, and no relay"))?;
                    Connector::Tcp(SocketAddr::from(([127, 0, 0, 1], port)))
                }
            };
            super::wait_healthy(&connector, Duration::from_secs(10)).await?;
            Ok(Sandbox {
                id: spec.id,
                template: spec.template,
                workspace_path: spec.workspace_path,
                connector,
                agent_token: Some(agent_token),
                peer_ip,
                created_at,
                ready_at: Some(now_rfc3339()),
                boot_ms: started.elapsed().as_millis() as u64,
            })
        })
    }

    fn destroy(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        // `timeout=0`: SIGKILL at once. Without it libpod's force remove still
        // waits out the 10 s stop grace, which also races the control plane's
        // 10 s forwarding timeout into a spurious 502.
        let name = format!("sbx-{}", sb.id);
        Box::pin(async move {
            self.table.lock().unwrap().remove(&name);
            let api = self.api();
            let (status, body) =
                self.call("DELETE", &format!("{api}/containers/{name}?force=true&v=true&timeout=0"), None).await?;
            if !(200..300).contains(&status) && status != 404 {
                anyhow::bail!("destroy {name}: {status} {}", String::from_utf8_lossy(&body));
            }
            Ok(())
        })
    }

    /// v5 §3a. One libpod `update`, which rewrites the running container's
    /// cgroup in place — this is what makes "one warm pool, resize at acquire"
    /// work. The container has `cap_drop ALL` and a read-only cgroupfs, so
    /// nothing inside can undo it.
    fn apply_limits(&self, sb: &Sandbox, l: &proto::SandboxLimits) -> BoxFut<'_, anyhow::Result<()>> {
        let name = format!("sbx-{}", sb.id);
        let body = if self.is_docker() { docker_limits(l) } else { resource_limits(l) };
        Box::pin(async move {
            self.json("POST", &format!("{}/containers/{name}/update", self.api()), Some(body)).await?;
            Ok(())
        })
    }

    fn usage(&self, sb: &Sandbox) -> BoxFut<'_, Option<proto::SandboxUsage>> {
        let (conn, token) = (sb.connector.clone(), sb.agent_token.clone());
        Box::pin(async move { super::guest_usage(&conn, token.as_deref()).await })
    }

    /// The container's own view of itself. A `404` is the one certain answer that
    /// it is gone; anything that is not a clear "not running" — podman
    /// unreachable, a reply we cannot parse — is not proof of death and reads as
    /// alive.
    fn alive(&self, sb: &Sandbox) -> BoxFut<'_, bool> {
        let name = format!("sbx-{}", sb.id);
        Box::pin(async move {
            match self.call("GET", &format!("{}/containers/{name}/json", self.api()), None).await {
                Ok((404, _)) => false,
                Ok((s, b)) if (200..300).contains(&s) => {
                    serde_json::from_slice::<Value>(&b).ok().is_none_or(|i| i["State"]["Running"] != false)
                }
                _ => true,
            }
        })
    }

    // ---------------------------------------------------------------- v4 lifecycle
    //
    // The container is kept, so installed packages and anything written outside
    // the bind-mounted workspace survive a stop; only the processes are gone.
    // Pause/resume/archive stay remote-only (§3a).

    fn supports_lifecycle(&self, verb: super::Verb) -> bool {
        matches!(verb, super::Verb::Stop | super::Verb::Start)
    }

    fn stop(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let name = format!("sbx-{}", sb.id);
        Box::pin(async move {
            // design: 2 s for SIGTERM before the SIGKILL. Nothing in a sandbox
            // owns state worth a long drain; raise it if a tier ever does.
            let stop = match self.is_docker() {
                true => format!("/containers/{name}/stop?t=2"),
                false => format!("{API}/containers/{name}/stop?timeout=2"),
            };
            self.json("POST", &stop, None).await?;
            Ok(())
        })
    }

    fn start(&self, sb: &Sandbox) -> BoxFut<'_, anyhow::Result<()>> {
        let (name, connector) = (format!("sbx-{}", sb.id), sb.connector.clone());
        Box::pin(async move {
            let api = self.api();
            self.json("POST", &format!("{api}/containers/{name}/start"), None).await?;
            // The port mapping was fixed at create, so the endpoint a client
            // holds still points here. Say so loudly if podman ever disagrees:
            // silently serving a different port would look like a hung sandbox.
            let info = self.json("GET", &format!("{api}/containers/{name}/json"), None).await?;
            match &connector {
                Connector::Tcp(a) => match Self::published_port(&info) {
                    Some(p) if p == a.port() => {}
                    other => anyhow::bail!("{name} came back on port {other:?}, not {}", a.port()),
                },
                // The address on the sandbox network is handed out per start: refresh it.
                Connector::Relay { name: n, .. } => {
                    let ip = info["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| anyhow::anyhow!("{name} came back with no address on {NETWORK}"))?;
                    self.table.lock().unwrap().insert(n.clone(), ip);
                }
                _ => {}
            }
            super::wait_healthy(&connector, Duration::from_secs(20)).await
        })
    }
}

// ------------------------------------------------------------------ image ops
//
// vm-tier template builds go through the socket's Docker-compatible endpoints,
// which podman and Docker both serve: a worker needs no CLI and no shell, which
// is what lets it run as a distroless container on either runtime. Pulls are
// anonymous on Docker (credentials live in the client there); podman's service
// uses root's `podman login`. ponytail: forward X-Registry-Auth from a config
// file when a private registry needs it.

async fn image_call(method: &str, path: &str, content_type: &str, body: Bytes) -> anyhow::Result<(u16, Bytes)> {
    let uri: hyper::Uri = hyperlocal::Uri::new(discover_socket()?, path).into();
    let req =
        hyper::Request::builder().method(method).uri(uri).header("content-type", content_type).body(Full::new(body))?;
    let resp = Client::unix().request(req).await?;
    let status = resp.status().as_u16();
    Ok((status, resp.into_body().collect().await?.to_bytes()))
}

/// Pull and build stream JSON lines and can answer 200 for a failure, which is
/// then a line with `error` in it.
fn streamed(what: &str, status: u16, body: &[u8]) -> anyhow::Result<()> {
    let text = String::from_utf8_lossy(body);
    let error = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find_map(|v| v["error"].as_str().map(String::from));
    match (200..300).contains(&status) && error.is_none() {
        true => Ok(()),
        false => anyhow::bail!(
            "{what}: {status} {}",
            error.unwrap_or_else(|| text.trim().lines().last().unwrap_or_default().chars().take(400).collect())
        ),
    }
}

fn plain(what: &str, (status, body): (u16, Bytes)) -> anyhow::Result<()> {
    anyhow::ensure!((200..300).contains(&status), "{what}: {status} {}", String::from_utf8_lossy(&body));
    Ok(())
}

/// `r` carries its tag or digest (`check_image_ref`).
pub async fn image_pull(r: &str) -> anyhow::Result<()> {
    let (s, b) = image_call("POST", &format!("/images/create?fromImage={r}"), "application/json", Bytes::new()).await?;
    streamed(&format!("pull {r}"), s, &b)
}

pub async fn image_tag(src: &str, repo: &str) -> anyhow::Result<()> {
    let path = format!("/images/{src}/tag?repo={repo}&tag=latest");
    plain(&format!("tag {src}"), image_call("POST", &path, "application/json", Bytes::new()).await?)
}

/// A context holding nothing but the Dockerfile: a Dockerfile template
/// describes an image, it does not build the daemon's working directory.
pub async fn image_build(dockerfile: &str, repo: &str) -> anyhow::Result<()> {
    let mut tar = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(dockerfile.len() as u64);
    h.set_mode(0o644);
    h.set_cksum();
    tar.append_data(&mut h, "Dockerfile", dockerfile.as_bytes())?;
    let context = Bytes::from(tar.into_inner()?);
    let path = format!("/build?t={repo}:latest&dockerfile=Dockerfile&rm=true&forcerm=true");
    let (s, b) = image_call("POST", &path, "application/x-tar", context).await?;
    streamed(&format!("build {repo}"), s, &b)
}

pub async fn image_commit(container: &str, repo: &str) -> anyhow::Result<()> {
    let path = format!("/commit?container={container}&repo={repo}&tag=latest");
    plain(&format!("commit {container}"), image_call("POST", &path, "application/json", Bytes::new()).await?)
}

/// The image's inspect body (`Id`, `Size`), or `None` when there is no such image.
pub async fn image_inspect(name: &str) -> Option<Value> {
    let (s, b) = image_call("GET", &format!("/images/{name}/json"), "application/json", Bytes::new()).await.ok()?;
    (200..300).contains(&s).then(|| serde_json::from_slice(&b).ok()).flatten()
}

/// An image's filesystem, unpacked into `dest` with its owners and modes: a
/// throwaway container labelled `sbx-snap=<label>` (so `remove_build_containers`
/// finds it if the daemon dies mid-export), its `/export` stream piped into
/// `tar`, the container removed again. Through the runtime's socket rather than
/// the CLI, so the privileged half runs in the runtime's service and qafas keeps
/// its narrow capability set.
pub async fn image_export(image: &str, label: &str, dest: &std::path::Path) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    let spec = json!({"Image": image, "Cmd": ["/bin/true"], "Labels": {"sbx-snap": label}});
    let (s, b) =
        image_call("POST", "/containers/create", "application/json", Bytes::from(serde_json::to_vec(&spec)?)).await?;
    anyhow::ensure!((200..300).contains(&s), "create from {image}: {s} {}", String::from_utf8_lossy(&b));
    let id = serde_json::from_slice::<Value>(&b)?["Id"].as_str().unwrap_or_default().to_string();
    let export = async {
        let uri: hyper::Uri = hyperlocal::Uri::new(discover_socket()?, &format!("/containers/{id}/export")).into();
        let resp = Client::unix().request(hyper::Request::get(uri).body(Full::new(Bytes::new()))?).await?;
        anyhow::ensure!(resp.status().is_success(), "export {image}: {}", resp.status());
        let mut tar = tokio::process::Command::new("tar")
            .args(["--numeric-owner", "-xpf", "-", "-C"])
            .arg(dest)
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        let mut stdin = tar.stdin.take().expect("piped");
        let mut body = resp.into_body();
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                stdin.write_all(&data).await?;
            }
        }
        drop(stdin);
        anyhow::ensure!(tar.wait().await?.success(), "unpacking {image} failed");
        Ok(())
    }
    .await;
    let _ = image_call("DELETE", &format!("/containers/{id}?force=true"), "", Bytes::new()).await;
    export
}

/// Every export container a template build left (`label` empty: all of them).
pub async fn remove_build_containers(label: &str) -> usize {
    let filter = if label.is_empty() { "sbx-snap".to_string() } else { format!("sbx-snap={label}") };
    let query = format!("/containers/json?all=true&filters={}", url_query(&json!({"label": [filter]}).to_string()));
    let Ok((200, b)) = image_call("GET", &query, "", Bytes::new()).await else { return 0 };
    let ids: Vec<String> = serde_json::from_slice::<Value>(&b)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.iter().filter_map(|c| c["Id"].as_str().map(String::from)).collect()))
        .unwrap_or_default();
    for id in &ids {
        let _ = image_call("DELETE", &format!("/containers/{id}?force=true"), "", Bytes::new()).await;
    }
    ids.len()
}

/// Percent-encodes a query value (the `filters` JSON).
fn url_query(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub async fn image_remove(name: &str) -> anyhow::Result<()> {
    plain(
        &format!("remove {name}"),
        image_call("DELETE", &format!("/images/{name}?force=true"), "", Bytes::new()).await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The proxy's address has to be the same one after every daemon restart,
    /// because every live sandbox already has it in its environment — and it has
    /// to be an address podman's IPAM will not hand to a sandbox.
    #[test]
    fn the_proxy_pins_the_top_of_whatever_subnet_the_network_has() {
        assert_eq!(proxy_ip_for("10.89.10.0/24").as_deref(), Some("10.89.10.254"));
        assert_eq!(proxy_ip_for("10.89.3.0/24").as_deref(), Some("10.89.3.254"));
        assert_eq!(proxy_ip_for("192.168.0.0/16").as_deref(), Some("192.168.255.254"));
        assert_eq!(proxy_ip_for("10.0.0.0/30").as_deref(), Some("10.0.0.2"));
        // Not the gateway, and inside the subnet.
        assert_ne!(proxy_ip_for("10.89.10.0/24").as_deref(), Some("10.89.10.1"));
        // Nothing usable: the caller falls back to a dynamic address.
        assert_eq!(proxy_ip_for("10.0.0.0/31"), None);
        assert_eq!(proxy_ip_for("fd00::/64"), None);
        assert_eq!(proxy_ip_for("10.89.10.0"), None);
    }

    fn podman() -> Podman {
        Podman {
            sock: "/dev/null".into(),
            http: Client::unix(),
            cfg: Arc::new(Config::resolve(crate::config::FileConfig::default())),
            docker: Default::default(),
            proxy_ip: std::sync::Mutex::new("10.0.0.2".into()),
            relay: std::sync::Mutex::new(None),
            table: Default::default(),
        }
    }

    fn docker() -> Podman {
        let p = podman();
        p.docker.store(true, std::sync::atomic::Ordering::Relaxed);
        p
    }

    /// D32: the same boundary in Docker's words — read-only rootfs, no
    /// capabilities, no_new_privs, the internal network, the size as cgroup
    /// limits — and, with no idmapped mounts, the workspace owner as the user.
    #[test]
    fn the_docker_spec_keeps_the_boundary_and_runs_as_the_workspace_owner() {
        use std::os::unix::fs::MetadataExt;
        let ws = std::env::temp_dir().join(format!("sbx-docker-ws-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let w = ws.to_str().unwrap().to_string();
        let s = docker().spec(&Spec { workspace_path: w.clone(), ..spec_for() }, 41000, "s3cret");
        let hc = &s["HostConfig"];
        assert_eq!(hc["ReadonlyRootfs"], true);
        assert_eq!(hc["CapDrop"], json!(["ALL"]));
        assert!(hc["SecurityOpt"].as_array().unwrap().iter().any(|o| o == "no-new-privileges"));
        assert_eq!(hc["NetworkMode"], NETWORK);
        assert!(hc.get("PortBindings").is_none(), "nothing is published; the relay is the way in");
        assert_eq!(hc["Memory"], 1024u64 * 1024 * 1024);
        assert_eq!(hc["MemorySwap"], hc["Memory"], "no swap");
        assert_eq!(hc["CpuQuota"], 100_000);
        assert_eq!(hc["PidsLimit"], 256);
        assert!(hc["Tmpfs"]["/tmp"].as_str().unwrap().contains("size=4096m"));
        assert_eq!(hc["Mounts"], json!([{"Type": "bind", "Source": w, "Target": w}]));
        let m = std::fs::metadata(&ws).unwrap();
        assert_eq!(s["User"], format!("{}:{}", m.uid(), m.gid()));
        assert!(s["Env"].as_array().unwrap().iter().any(|e| e == "SBX_AGENT_TOKEN=s3cret"));

        let bare = docker().spec(&Spec { workspace_path: "/home/agent".into(), ..spec_for() }, 41000, "t");
        assert_eq!(bare["User"], "1000:1000");
        assert_eq!(bare["HostConfig"]["Mounts"], json!([]));
        let _ = std::fs::remove_dir(&ws);
    }

    #[test]
    fn docker_refuses_a_root_owned_workspace_and_podman_does_not() {
        // `/` is root's on every host this runs on.
        assert!(docker().refuse_workspace("/").is_some());
        assert!(docker().refuse_workspace("/home/agent").is_none(), "no workspace, nothing to own");
        assert!(docker().refuse_workspace("/nonexistent/sbx-ws").is_some(), "never created as root");
        assert!(!std::path::Path::new("/nonexistent").exists());
        let mine = std::env::temp_dir();
        if std::fs::metadata(&mine).map(|m| std::os::unix::fs::MetadataExt::uid(&m) != 0).unwrap_or(false) {
            assert!(docker().refuse_workspace(mine.to_str().unwrap()).is_none(), "a user's own directory");
        }
        assert!(podman().refuse_workspace("/").is_none(), "podman maps the owner instead");
    }

    #[test]
    fn docker_below_26_is_refused() {
        assert!(docker_supported("25.0.5").is_err());
        assert!(docker_supported("").is_err());
        assert!(docker_supported("26.0.0").is_ok());
        assert!(docker_supported("28.3.1").is_ok());
    }

    #[test]
    fn a_streamed_error_line_is_a_failure_even_on_200() {
        assert!(streamed("pull", 200, b"{\"status\":\"Pulling\"}\n{\"status\":\"Done\"}").is_ok());
        let e = streamed("pull", 200, b"{\"status\":\"x\"}\n{\"error\":\"denied\"}").unwrap_err();
        assert!(e.to_string().contains("denied"), "{e}");
        assert!(streamed("build", 500, b"boom").is_err());
    }

    fn spec_for() -> Spec {
        Spec {
            id: "sbx_1".into(),
            template: "base".into(),
            workspace_path: "/w".into(),
            egress_allow: vec![],
            image: String::new(),
            snapshot: None,
            env: Default::default(),
            pi_session: String::new(),
            limits: proto::sizes::default_table()["mini"],
        }
    }

    /// v5 §3a: the container's cgroup is the size, and the `update` body that
    /// resizes a pooled container at acquire is the identical block.
    #[test]
    fn the_spec_carries_the_size_as_cgroup_limits() {
        let s = podman().spec(&spec_for(), 41000, "t");
        let want = json!({
            "memory": {"limit": 1024u64 * 1024 * 1024},
            "cpu": {"quota": 100_000, "period": 100_000},
            "pids": {"limit": 256},
        });
        assert_eq!(s["resource_limits"], want, "mini = 1 cpu / 1 GiB / 256 pids");
        assert_eq!(
            resource_limits(&proto::sizes::default_table()["micro"])["cpu"]["quota"],
            50_000,
            "a fractional size is a fractional quota"
        );

        // The scratch tmpfs is the largest configured size, not this one: a
        // pooled container keeps the mount it was created with.
        let tmp = s["mounts"].as_array().unwrap().iter().find(|m| m["destination"] == "/tmp").unwrap().clone();
        assert!(tmp["options"].as_array().unwrap().iter().any(|o| o == "size=4096m"), "{tmp}");
    }

    /// v4 §2: the published loopback port is not a boundary, so the container
    /// carries the secret that is. It lives in the container environment, which
    /// is what makes it survive stop/start.
    #[test]
    fn the_container_spec_carries_the_agent_token() {
        let s = podman().spec(&spec_for(), 41000, "s3cret");
        assert_eq!(s["env"]["SBX_AGENT_TOKEN"], "s3cret");
        // And nothing inside can read it back: it is a protected name, so an
        // exec can neither see it in its own environment nor override it.
        assert!(!agent_core::spawn::env_allowed("SBX_AGENT_TOKEN"));
    }

    /// v4c §3a: the workspace is optional. With none named the container works in
    /// its own `/home/agent` — the tmpfs it already has — and nothing from the
    /// host is bind-mounted in. A named path is still mounted at the same path.
    #[test]
    fn no_workspace_means_no_bind_mount() {
        let mounts = |w: &str| {
            let s = podman().spec(&Spec { workspace_path: w.into(), ..spec_for() }, 41000, "t");
            (s["mounts"].as_array().unwrap().clone(), s["work_dir"].clone())
        };
        let (bare, cwd) = mounts("/home/agent");
        assert_eq!(cwd, "/home/agent");
        assert!(!bare.iter().any(|m| m["type"] == "bind"), "{bare:?}");

        let (named, cwd) = mounts("/w");
        assert_eq!(cwd, "/w");
        let bind = named.iter().find(|m| m["type"] == "bind").expect("the named path is mounted");
        assert_eq!(bind["destination"], "/w", "at the identical path, in and out");
        assert_eq!(bind["source"], "/w");
    }

    /// A fresh 32-byte secret per sandbox, never a reused one.
    #[test]
    fn minted_tokens_are_long_and_unique() {
        let a = super::super::mint_agent_token().unwrap();
        let b = super::super::mint_agent_token().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
