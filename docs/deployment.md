# Production deployment

How to run Qafas Sandbox beyond one machine: a control plane (the **server**) and any number of workers (the **agents**), each on its own host. It covers requirements, network and firewall rules, OS permissions, the install methods, TLS, egress, and day-2 operations. To try it on one machine first, see the [README](../README.md). For a datacenter with no internet, follow [airgap.md](airgap.md) after reading this.

```sh
V=0.8.1      # the release every command below installs  (x-release-please-version)
```

## 1. Roles

| role | what runs | how many |
|---|---|---|
| **Control plane** (server) | `controlplane` — the API, the dashboard, placement, alerts, the event history in SQLite | one per site |
| **Worker** (agent) | `qafas` — the sandboxes on this host, their egress proxy, their telemetry | one per sandbox host |
| **Clients** | the `sbx` CLI, the SDKs, coding agents (Claude Code, Codex, Cursor, pi) | anywhere that can reach both of the above |

- A worker **registers itself**: it dials the control plane at start, then sends a heartbeat every 10 s and its events every second. The control plane keeps no host list of its own; a worker silent for 30 s is skipped by placement.
- A client asks the control plane for a sandbox and gets back the worker's address and a token scoped to that sandbox; exec, files, the shell and the browser then go **straight to the worker**. Clients therefore need a route to every worker, not only to the control plane.
- Each worker serves **one pooled runtime**: `vm` (containers on Docker or podman) or `remote` (Firecracker microVMs). A host that can do both serves `remote`. `native` runs commands as the daemon's own user, so it belongs only on a trusted developer machine, never on a root-run worker.
- Workers never talk to each other. Capacity is a calculation (section 2), not autoscaling.

```
 ┌──────────── client segment ────────────┐
 │  sbx CLI · SDKs · coding agents · browser│
 └───────┬──────────────────────┬─────────┘
         │ :7800                │ :7700 (data path)
 ┌───────▼────────┐  :7700  ┌───▼────────────────────────────┐
 │ control plane  ├────────►│ worker 1 … worker N            │
 │ :7800 + SQLite │◄────────┤ qafas + Docker/podman or KVM   │
 └────────────────┘  :7800  └───┬────────────────────────────┘
                                 │ sandbox egress (allowlist only), from the worker's own IP
                                 ▼
                       package mirrors / allowed sites
```

## 2. Requirements

### Operating system

| | |
|---|---|
| Architectures | x86_64 and aarch64 (arm64), for every component |
| Validated | Ubuntu 24.04, Linux Mint 22, Rocky Linux 9 (so RHEL, Alma, CentOS Stream 9) |
| Expected to work | any systemd distribution with cgroup v2 |
| RHEL family | SELinux may stay enforcing; `vm` sandboxes then run with SELinux labelling off for their container (the workspace keeps its labels; `docs/security.md` M42). The CLI needs Node.js 22: `dnf module enable nodejs:22`. |
| Ubuntu / Mint | nothing extra. Node.js 22 for the CLI from NodeSource, or use the `sbx` container image. |

### Per role

| role | needs |
|---|---|
| control plane | nothing beyond the OS: a static binary with the dashboard built in (or the `controlplane` container) |
| `vm` worker | **Docker Engine 26+** or **podman 4.4+** with `podman.socket`; cgroup v2. Docker below 26 is refused at start (its internal networks forwarded DNS outside, CVE-2024-29018). |
| `remote` worker | `/dev/kvm` (bare metal, or nested virtualisation), cgroup v2, `nft` (nftables), `ip` (iproute2), `mkfs.ext4` (e2fsprogs), podman for building templates, and the `qafas-firecracker` bundle (section 5.4) |
| `native` (dev only) | macOS 14+; Linux bwrap + Landlock is compile-checked only |

### Sizing

**Workers.** Every sandbox has a fixed size, and placement never overcommits by default, so a worker's capacity is its CPUs and memory divided by the sizes you run:

| size | CPUs | memory | scratch disk | processes |
|---|---|---|---|---|
| `micro` | 0.5 | 512 MiB | 512 MiB | 128 |
| `mini` | 1 | 1 GiB | 1 GiB | 256 |
| `medium` (default) | 2 | 2 GiB | 2 GiB | 512 |
| `high` | 4 | 4 GiB | 4 GiB | 1024 |

- A 16 vCPU / 64 GiB worker runs 8 `medium` sandboxes (CPU-bound: 16 ÷ 2), or 16 `mini`. Leave 1–2 GiB for the host itself.
- Scratch disk is RAM-backed, so memory is what runs out first when sandboxes fill `/tmp`.
- Cap a host below its hardware with `max_cpus`, `max_mem_mib`, `max_disk_mib` in `/etc/qafas/qafas.toml`; overcommit deliberately with `SBX_OVERCOMMIT_CPU` / `SBX_OVERCOMMIT_MEM` on the control plane (default 1.0).
- Disk: the guest image is about 1.4 GB; each template adds its image (`vm`) or a 2 GiB disk plus a memory capture the size of its RAM (`remote`). Templates have no quota — size `/var/lib/qafas` for the templates you plan to keep.
- A Firecracker worker runs at most **126** microVMs, and serves the `high` size only with `[firecracker] mem_mib = 4096` or more (the guest's RAM is fixed by its template).

**Control plane.** 2 vCPUs and 2–4 GiB RAM serve a small-to-medium fleet; SQLite takes on the order of 2,000 events a second. Its disk grows with the event history (`SBX_RETENTION_DAYS`, default 30); start with 20 GiB and watch `/var/lib/controlplane`.

### Address ranges a worker uses

Each worker creates networks of its own; none may overlap a range the worker needs to reach in your datacenter.

| runtime | range | change it with |
|---|---|---|
| Docker | the daemon's default pools (`172.17.0.0/16` and up, `192.168.x.0/20`) | `default-address-pools` in `/etc/docker/daemon.json`, before the first start |
| podman | `10.89.x.0/24` for the `sbx-internal` network | `default_subnet_pools` in `/etc/containers/containers.conf` |
| Firecracker | one `/30` per microVM in `172.16.1.0`–`172.16.126.255` | fixed in this release: keep that range off routes the worker needs |

## 3. Networking

Inbound rules (everything else can be denied):

| Port | Protocol | Source | Destination | Description |
|---|---|---|---|---|
| 7800 | TCP | clients, browsers | control plane | API, dashboard, event stream |
| 7800 | TCP | workers | control plane | registration, heartbeats (10 s), events (1 s batches) |
| 7800 | TCP | Prometheus (optional) | control plane | metrics; worker metrics are fetched *through* the control plane |
| 7700 | TCP | control plane | workers | create, destroy, lifecycle, worker metrics, preview URLs |
| 7700 | TCP | clients | workers | the data path: exec, files, shell and browser (WebSocket) |
| 22 | TCP | admin bastion | all | SSH, as your site requires |

Never reachable from off the host: **3128** (the egress proxy — on a Firecracker worker it listens on every interface and qafas drops it everywhere but the microVM taps; on a `vm` worker it lives inside a container) and **3129** (the proxy's relay, on the container runtime's bridge).

Outbound:

| from | to | when |
|---|---|---|
| workers | allow-listed destinations, usually TCP 443/80 | sandbox egress: the proxy runs on the worker, so traffic leaves from the **worker's own IP** — perimeter rules key on worker IPs |
| workers | DNS, UDP/TCP 53 | the proxy resolves allow-listed names on the worker; sandboxes have no resolver of their own |
| workers | your registry, TCP 443 | only when the guest image or a template's base image is not pre-loaded |
| control plane | your OTLP receiver | only if trace export is switched on |
| all | NTP | recommended: events carry the worker's clock |

A multi-host worker must set **`public_url`** to the address clients and the control plane dial (`http://worker-1.example:7700`); without it the worker registers `127.0.0.1`.

Host firewall examples:

```sh
# ufw — control plane
sudo ufw allow from 10.0.10.0/24 to any port 7800 proto tcp     # clients
sudo ufw allow from 10.0.20.0/24 to any port 7800 proto tcp     # workers
# ufw — worker
sudo ufw allow from 10.0.1.5 to any port 7700 proto tcp         # the control plane
sudo ufw allow from 10.0.10.0/24 to any port 7700 proto tcp     # clients

# firewalld — the same on RHEL
sudo firewall-cmd --permanent --new-zone=qafas
sudo firewall-cmd --permanent --zone=qafas --add-source=10.0.10.0/24 --add-port=7700/tcp
sudo firewall-cmd --reload
```

Docker writes its own iptables/nftables rules. Qafas publishes no sandbox ports (Docker cannot publish from an internal network, and podman binds loopback only), and the compose file uses host networking, so the rules above are the whole picture.

## 4. OS permissions

**`qafas` runs as root** under systemd, because it drives the container runtime's root socket, creates idmapped mounts, tap devices and nftables rules, and starts the Firecracker jailer. The unit narrows that:

- capabilities (bounding set): `CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE`, plus `CAP_FOWNER CAP_MKNOD CAP_KILL` for the Firecracker jailer and for stopping microVMs (`/usr/lib/systemd/system/qafas.service` says which needs what);
- `ProtectSystem=full` (`/usr`, `/boot`, `/etc` read-only), `ProtectKernelModules`, `ProtectKernelLogs`, `RestrictRealtime`, `LockPersonality`;
- `NoNewPrivileges=no` and `ProtectHome=no` on purpose: the jailer changes uid, and workspaces live under `/home`.

**The container runtime's socket is root-equivalent.** `/var/run/docker.sock` or `/run/podman/podman.sock` belongs to qafas alone; in the container install the `qafas` container holds it, so treat that container as root on the host.

**`controlplane` runs as the unprivileged `controlplane` user** with no capabilities, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateDevices=yes`; it writes only `/var/lib/controlplane`.

**Sandboxes** have an empty capability set, `no_new_privs`, a seccomp filter, a read-only root filesystem and no network but the proxy. They run as uid 1000 on podman and Firecracker, with the workspace mapped so that writes land as the directory's owner; on Docker, which has no idmapped mounts, they run as the workspace's owner directly, and a root-owned workspace is refused. Give each user a workspace they own (their home directory is the usual one).

| path | mode | holds |
|---|---|---|
| `/etc/controlplane/env` | 0640 root:controlplane | the three control-plane tokens, listen address, TLS paths |
| `/etc/qafas/qafas.toml` | 0640 root:root | the worker's token and host token, tiers, control-plane URL |
| `/etc/qafas/egress.json` | 0644 | the egress allowlist |
| `/var/lib/controlplane/` | controlplane | `sandbox.db` |
| `/var/lib/qafas/` | root | TLS pair, templates and their scans, the sandbox table, spooled events, the Firecracker bundle and jails |

## 5. Install methods

### 5.1 Packages (recommended)

Download as in the README (`qafas-controlplane`, `qafas`, `qafas-cli`, `SHA256SUMS`) and check the sums.

**Server** — on the control-plane host:

```sh
sudo apt install ./qafas-controlplane_$V-1_$A.deb             # or: sudo dnf install ./qafas-controlplane-$V-1.$A.rpm
sudo grep -E '^SBX_(ADMIN|HOST)_TOKEN|^SBX_TOKEN_SECRET' /etc/controlplane/env   # minted on install; keep them safe
```

**Agents** — on each worker:

```sh
sudo apt install ./qafas_$V-1_$A.deb                          # or: sudo dnf install ./qafas-$V-1.$A.rpm
sudo editor /etc/qafas/qafas.toml
```

```toml
cp_url     = "http://cp.example:7800"         # https://… once the control plane has TLS (section 6)
host_token = "<SBX_HOST_TOKEN from the server>"
token      = "<SBX_TOKEN_SECRET from the server>"
public_url = "http://worker-1.example:7700"   # what clients and the control plane dial
# ca_file  = "/etc/qafas/ca.crt"              # the CA an https cp_url chains to
```

```sh
sudo systemctl restart qafas
curl -s -H "Authorization: Bearer $SBX_ADMIN_TOKEN" http://cp.example:7800/api/hosts   # the worker, its tiers and capacity
```

**Clients** — `qafas-cli` (Node.js 22) gives `sbx` and the TypeScript SDK; or the `sbx` container image.

Every key, with its default: `/usr/share/doc/qafas/qafas.toml.example`. Environment variables (`SBX_*`) override the file; the package pins the guest image that way (`/usr/lib/systemd/system/qafas.service.d/image.conf`) so it follows each upgrade.

### 5.2 Containers

The images `ghcr.io/exitcodenihil/qafas-sandbox/{controlplane,qafas,sbx}:$V` run from one compose file, per role (`deploy/docker/compose.yml`, `deploy/docker/.env.example`):

```sh
# server
docker compose up -d controlplane
# each agent: .env holds the same tokens, plus
#   SBX_HOST_ID=worker-1  SBX_CP_URL=http://cp.example:7800  SBX_PUBLIC_URL=http://worker-1.example:7700
docker compose up -d qafas
```

The `qafas` container serves the `vm` tier through the host's Docker (or podman: `CONTAINER_SOCK=/run/podman/podman.sock`), so the sandboxes are ordinary host containers with the same boundary as the package install. Mount every directory people work in at the same path (`/home` and `/root` are there already), and your own `egress.json` over `/etc/qafas/egress.json`. The control plane's TLS pair mounts into its container (`SBX_TLS_CERT`, `SBX_TLS_KEY`).

### 5.3 By hand, from the tarball

`qafas-$V-linux-<arch>.tar.gz` holds `bin/{qafas,guest-agent,controlplane}` and `deploy/` (the systemd units, `env.example`, `qafas.toml`):

```sh
sudo install -m755 bin/qafas bin/controlplane /usr/bin/
sudo useradd --system --home /var/lib/controlplane --shell /usr/sbin/nologin controlplane
sudo install -Dm640 -g controlplane deploy/controlplane/env.example /etc/controlplane/env     # fill in the tokens
sudo install -Dm640 deploy/qafas.toml /etc/qafas/qafas.toml                                   # the full reference
sudo install -m644 deploy/systemd/qafas.service deploy/controlplane/controlplane.service /etc/systemd/system/
# pin the guest image to this version, as the package does
printf '[Service]\nEnvironment=SBX_TEMPLATE_IMAGE=ghcr.io/exitcodenihil/qafas-sandbox/sbx-base:%s\n' $V |
  sudo install -Dm644 /dev/stdin /etc/systemd/system/qafas.service.d/image.conf
sudo systemctl daemon-reload && sudo systemctl enable --now controlplane qafas
```

The guest image and the daemon must be the same version: the egress proxy runs the `qafas` binary from inside that image.

### 5.4 Firecracker workers (`remote` tier)

The release ships `qafas-firecracker-$V-<x86_64|aarch64>.tar.zst`: Firecracker and its jailer, a guest kernel, the guest root filesystem built from this release's image, and the guest agent — laid out against `/`.

```sh
sudo apt install ./qafas_$V-1_$A.deb nftables iproute2 e2fsprogs   # the worker package, as in 5.1
sudo tar --zstd -xpmf qafas-firecracker-$V-$(uname -m).tar.zst -C /
ls /dev/kvm && sudo /usr/bin/qafas doctor                           # kvm and firecracker: ok
sudo sed -i 's/^tiers .*/tiers      = ["remote"]/' /etc/qafas/qafas.toml
sudo systemctl restart qafas
sudo journalctl -u qafas -n 30 --no-pager                           # "base memory snapshot captured", then the pool fills
```

- The packaged config already points `[firecracker]` at the bundle and keeps the jail at `/var/lib/qafas/jail`, on the same filesystem as the templates, so disks and memory captures are hard links rather than copies.
- `[firecracker] mem_mib` (default 2048) is every guest's RAM; raise it to 4096 to serve `high`.
- Every template is a memory capture, so a create is a restore (tens of milliseconds pooled, about a second cold) rather than a boot. Huge pages (`hugepages = true`) speed up nested virtualisation but rule out captures, stop/start and archives — leave them off unless you know you want that trade.
- The bundled kernel has no BTF, so in-guest process telemetry samples `/proc` every 25 ms instead of using eBPF. For eBPF, build a guest kernel from Firecracker's `microvm-kernel-ci-<arch>-6.1.config` with `DEBUG_INFO_BTF`, `BPF_SYSCALL`, `BPF_EVENTS`, `FTRACE_SYSCALLS`, `OVERLAY_FS` on and `FUNCTION_TRACER` off, and point `[firecracker] kernel` at it.
- Extracting with `-m` matters on upgrade: the new files get the current time, which tells qafas to recapture `base`.

**Host hardening.** A microVM boundary is only as good as the host under it. On a worker that runs untrusted code from more than one party:

- turn simultaneous multithreading off (`nosmt` on the kernel command line, or `echo off > /sys/devices/system/cpu/smt/control`), which closes cross-guest side channels between sibling threads;
- turn kernel samepage merging off (`echo 0 > /sys/kernel/mm/ksm/run`) and run without swap, so one guest's memory is never shared with or written out beside another's;
- keep the host kernel and microcode current;
- on a cloud VM, set the instance metadata service to IMDSv2 with a hop limit of 1, so nothing forwarded from the host can reach it (sandboxes already cannot: link-local is always denied).

## 6. Tokens and TLS

| secret | set on | presented by | to | for |
|---|---|---|---|---|
| `SBX_ADMIN_TOKEN` | control plane | people, the CLI, admin scripts | control plane | everything |
| API keys | dashboard → API keys | agents, SDKs (`SBX_API_KEY`) | control plane | their own sandboxes, within the sizes and tiers the key allows |
| `SBX_HOST_TOKEN` = worker `host_token` | both | workers (and Prometheus) | control plane | registering and reporting |
| `SBX_TOKEN_SECRET` = worker `token` | both | control plane | workers | administering a worker; the worker signs per-sandbox tokens with it |
| per-sandbox token | minted by the worker | clients | that worker, that sandbox only | 12 hours (`token_ttl_secs`) |

Whoever holds `SBX_HOST_TOKEN` can register a worker under any name: treat it like the admin token. To rotate a token, change it on both sides and restart both services.

**TLS on the control plane.** Put a certificate and key from your CA on the server, readable by the `controlplane` group, and add to `/etc/controlplane/env`:

```sh
SBX_TLS_CERT=/etc/controlplane/tls.crt
SBX_TLS_KEY=/etc/controlplane/tls.key
```

Workers then use `cp_url = "https://cp.example:7800"` and `ca_file` (or a CA in the system bundle). The CLI and the SDKs trust the same CA through `SBX_CA_FILE` (Node also honours `NODE_EXTRA_CA_CERTS`); browsers through the OS trust store.

**TLS on workers.** `tls = true` in `qafas.toml` serves the worker API, WebSockets included, over HTTPS:

- with `tls_cert` / `tls_key` from your CA, and `SBX_CA_FILE` on the control plane pointing at that CA, every hop is verified against the CA (recommended);
- without them, the worker generates a self-signed pair once into `/var/lib/qafas/tls`, and the control plane pins its fingerprint at registration (trust on first use, guarded by `SBX_HOST_TOKEN`); clients receive the pin with each sandbox and verify against it.

The certificate's names must include what `public_url` says. Check a pin by hand: `openssl x509 -in /var/lib/qafas/tls/cert.pem -noout -fingerprint -sha256`.

## 7. Egress

Every sandbox's only way out is the proxy on its worker, which reads `/etc/qafas/egress.json` at start (restart `qafas` after editing):

```json
{
  "allow": ["github.com", "*.github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"],
  "deny_cidrs_extra": ["203.0.113.0/24"],
  "allow_private_cidrs": []
}
```

- A destination must match an `allow` glob **and** resolve to a public address. Loopback, private ranges, link-local (so `169.254.169.254`), CGNAT and multicast are refused whatever `allow` says.
- **Internal mirrors:** list their private range in `allow_private_cidrs` and their names in `allow` — `"allow": ["nexus.corp.example"], "allow_private_cidrs": ["10.20.0.0/16"]`. Only RFC1918 and IPv6 unique-local ranges can be opened; loopback, link-local and CGNAT stay shut.
- A harness may add names for one sandbox (`egress_allow` on create; an API key can limit which names its holder may add); it can never add ranges. The model inside the sandbox can change nothing.
- Every refusal is an `egress.deny` event, and probes of metadata endpoints raise alerts, on the dashboard's **Alerts** page.

## 8. Operations

### Upgrades

1. On a worker that cannot pull, load the new guest image first (`airgap.md`): the new package pins it, and a worker whose image is missing does not start.
2. Upgrade the control plane, then the workers, with the same `apt`/`dnf install` command and the new files. Your edited config files are kept: when the packaged default changed too, apt asks — keep yours (`N`; unattended, `apt-get -o Dpkg::Options::=--force-confold install …`) and compare it with the new default it leaves beside it (`qafas.toml.dpkg-dist`); dnf keeps yours without asking and writes `.rpmnew`. Database migrations run forward on start.
3. On Firecracker workers, extract the new bundle with `tar -m` before restarting `qafas`; the `base` capture is redone automatically.
4. Rebuild your own templates after an upgrade (dashboard → Templates → delete and recreate, or the API): they carry the guest agent from when they were built.

A worker restart destroys its running `vm` sandboxes; `remote` sandboxes are paused to disk and resumed.

### Backups

- Control plane: `sudo sqlite3 /var/lib/controlplane/sandbox.db ".backup '/backup/sandbox-$(date +%F).db'"` (safe while running), plus `/etc/controlplane/env`. Restore: stop the service, put the file back, start it. Workers re-register by themselves.
- Workers: `/etc/qafas/` and `/var/lib/qafas/tls/` (its pinned certificate). Templates can be rebuilt; the rest is per-sandbox state.

### Monitoring

- The control plane serves `GET /metrics` (`sbxcp_*`) and `GET /api/prometheus/targets`, a service-discovery list that routes every worker's metrics (`sbx_*`) through the control plane — Prometheus needs no route to the workers. Authenticate with `SBX_HOST_TOKEN` or the admin token.
- `deploy/monitoring/` is a ready Prometheus, Alertmanager, Grafana (fleet, security and control-plane dashboards), Jaeger and node-exporter stack: `cp .env.example .env`, set the token, `make monitoring-up`. It scrapes the control plane on the same machine; for another machine, edit the two addresses in `prometheus.yml`.
- Traces: the dashboard's **Settings → Observability** pushes OTLP/HTTP to a receiver you run (Jaeger, Tempo, Langfuse self-hosted).

### Troubleshooting

| symptom | look at |
|---|---|
| a worker is missing from **Hosts** | `journalctl -u qafas` for "host register failed": `cp_url`, `host_token`, the firewall on 7800, and `ca_file` for an https control plane |
| it is listed, but sandboxes fail to start | `public_url` is reachable from the control plane and the clients on 7700 |
| `no tier available on this host` | `sudo qafas doctor`: the runtime socket, `/dev/kvm`, the Firecracker files |
| `Docker Engine … is too old` | upgrade to Docker 26 or later |
| `… is owned by root` / `… does not exist; on the Docker runtime …` | run from an existing directory a regular user owns |
| `pull …: …` on first start | the guest image is not loaded and the registry is unreachable: load it (`airgap.md`) |
| `mem_mib … exceeds this host's template RAM` | raise `[firecracker] mem_mib`, or ask for a smaller size |
| `template … failed its security scan` | an untrusted sandbox asked for an F-graded template: open it under **Templates** to see why |

### Known limits

- One control plane, SQLite, no high availability: keep backups.
- A worker serves one pooled runtime.
- The Firecracker `/30` range and the 126-microVM limit are fixed in this release.
- Template pulls on Docker are anonymous: pre-load private base images, or use a registry that allows anonymous pulls on the internal network.
