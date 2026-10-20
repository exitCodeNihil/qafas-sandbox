# Production deployment

This guide is for operators who install and run Qafas Sandbox on more than one host: one control plane (the server) and any number of workers (the agents), each on its own host. Read it top to bottom: what runs where, what to prepare, how to install, how to secure it, and how to run it day to day.

- To try Qafas on one machine first, use the [README](../README.md) quick start.
- For a datacenter with no internet, read this guide, then follow [airgap.md](airgap.md).

Every command below installs this release:

```sh
V=0.3.2      # the release every command below installs  (x-release-please-version)
```

## Contents

1. [Roles](#1-roles): what runs where, and how the pieces talk
2. [Requirements](#2-requirements): operating system, per-role needs, sizing, address ranges
3. [Networking](#3-networking): ports and firewall rules
4. [OS permissions](#4-os-permissions): users, capabilities, file modes
5. [Install methods](#5-install-methods): packages, containers, tarball, Firecracker workers, `native` on Linux
6. [Tokens and TLS](#6-tokens-and-tls)
7. [Egress](#7-egress): what sandboxes may reach
8. [Operations](#8-operations): upgrades, backups, monitoring, troubleshooting, known limits

## 1. Roles

| Role | What runs | How many |
|---|---|---|
| Control plane (server) | `controlplane`: the API, the dashboard, placement, alerts, the event history in SQLite | one per site |
| Worker (agent) | `qafas`: the sandboxes on this host, their egress proxy, their telemetry | one per sandbox host |
| Clients | the `sbx` CLI, the SDKs, coding agents (Claude Code, Codex, Cursor, pi) | anywhere that can reach both of the above |

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

How the pieces work together:

- Workers register themselves. A worker dials the control plane at start, then sends a heartbeat every 10 s and its events every second. The control plane keeps no host list of its own, and placement skips a worker that has been silent for 30 s.
- Clients talk to workers directly. A client asks the control plane for a sandbox and gets back the worker's address and a token scoped to that sandbox. Exec, files, the shell and the browser then go straight to the worker, so clients need a route to every worker, not only to the control plane.
- Each worker serves one pooled runtime: `vm` (containers on Docker or podman) or `remote` (Firecracker microVMs). A host that can do both serves `remote`.
- `native` runs commands as the daemon's own user, so it belongs only on a trusted developer machine, never on a root-run worker (section 5.5).
- Workers never talk to each other. Capacity is a calculation (section 2), not autoscaling.

## 2. Requirements

### Operating system

| Item | Requirement |
|---|---|
| Architectures | x86_64 and aarch64 (arm64), for every component |
| Validated | Ubuntu 24.04, Linux Mint 22, Rocky Linux 9 (so RHEL, Alma, CentOS Stream 9) |
| Expected to work | any systemd distribution with cgroup v2 |
| RHEL family | SELinux may stay enforcing; `vm` sandboxes then run with SELinux labelling off for their container (the workspace keeps its labels; [security.md](security.md) M42). The CLI needs Node.js 22: `dnf module enable nodejs:22`. |
| Ubuntu / Mint | nothing extra. Node.js 22 for the CLI from NodeSource, or use the `sbx` container image. |

### Per role

| Role | Needs |
|---|---|
| control plane | nothing beyond the OS: a static binary with the dashboard built in (or the `controlplane` container) |
| `vm` worker | Docker Engine 26+ or podman 4.4+ with `podman.socket`; cgroup v2. Docker below 26 is refused at start (its internal networks forwarded DNS outside, CVE-2024-29018). Optionally a sandboxing OCI runtime (gVisor `runsc`, Kata) registered with the engine (section 5.1, "Sandbox runtime"). |
| `remote` worker | `/dev/kvm` (bare metal, or nested virtualisation), cgroup v2, `nft` (nftables), `ip` (iproute2), `mkfs.ext4` (e2fsprogs), podman for building templates, and the `qafas-firecracker` bundle (section 5.4) |
| `native` (dev only) | macOS 14+: Seatbelt (`/usr/bin/sandbox-exec`). Linux: `bwrap` (bubblewrap) on `PATH`, Landlock in the kernel (ABI 2+), and `qafas` running as the developer's own user, never as root (section 5.5). |

### Sizing

#### Workers

Every sandbox has a fixed size, and placement never overcommits by default. A worker's capacity is therefore its CPUs and memory divided by the sizes you run:

| Size | CPUs | Memory | Scratch disk | Processes |
|---|---|---|---|---|
| `micro` | 0.5 | 512 MiB | 512 MiB | 128 |
| `mini` | 1 | 1 GiB | 1 GiB | 256 |
| `medium` (default) | 2 | 2 GiB | 2 GiB | 512 |
| `high` | 4 | 4 GiB | 4 GiB | 1024 |

- Example: a 16 vCPU / 64 GiB worker runs 8 `medium` sandboxes (CPU-bound: 16 ÷ 2), or 16 `mini`. Leave 1–2 GiB for the host itself.
- Scratch disk is RAM-backed, so memory is what runs out first when sandboxes fill `/tmp`.
- To cap a host below its hardware, set `max_cpus`, `max_mem_mib`, `max_disk_mib` in `/etc/qafas/qafas.toml`.
- To overcommit deliberately, set `SBX_OVERCOMMIT_CPU` / `SBX_OVERCOMMIT_MEM` on the control plane (default 1.0).
- Disk: the guest image is about 1.4 GB. Each template adds its image (`vm`) or a 2 GiB disk plus a memory capture the size of its RAM (`remote`). Templates have no quota, so size `/var/lib/qafas` for the templates you plan to keep.
- A Firecracker worker runs at most 126 microVMs. It serves the `high` size only with `[firecracker] mem_mib = 4096` or more (the guest's RAM is fixed by its template).

#### Control plane

- 2 vCPUs and 2–4 GiB RAM serve a small-to-medium fleet.
- SQLite takes on the order of 2,000 events a second.
- Its disk grows with the event history (`SBX_RETENTION_DAYS`, default 30). Start with 20 GiB and watch `/var/lib/controlplane`.

### Address ranges a worker uses

Each worker creates networks of its own. None of them may overlap a range the worker needs to reach in your datacenter.

| Runtime | Range | Change it with |
|---|---|---|
| Docker | the daemon's default pools (`172.17.0.0/16` and up, `192.168.x.0/20`) | `default-address-pools` in `/etc/docker/daemon.json`, before the first start |
| podman | `10.89.x.0/24` for the `sbx-internal` network | `default_subnet_pools` in `/etc/containers/containers.conf` |
| Firecracker | one `/30` per microVM in `172.16.1.0`–`172.16.126.255` | fixed in this release: keep that range off routes the worker needs |

## 3. Networking

### Inbound

Allow these; everything else can be denied.

| Port | Protocol | Source | Destination | Description |
|---|---|---|---|---|
| 7800 | TCP | clients, browsers | control plane | API, dashboard, event stream |
| 7800 | TCP | workers | control plane | registration, heartbeats (10 s), events (1 s batches) |
| 7800 | TCP | Prometheus (optional) | control plane | metrics; worker metrics are fetched *through* the control plane |
| 7700 | TCP | control plane | workers | create, destroy, lifecycle, worker metrics, preview URLs |
| 7700 | TCP | clients | workers | the data path: exec, files, shell and browser (WebSocket) |
| 22 | TCP | admin bastion | all | SSH, as your site requires |

Never make these reachable from off the host:

- 3128, the egress proxy. On a Firecracker worker it listens on every interface and qafas drops it everywhere but the microVM taps. On a `vm` worker it lives inside a container.
- 3129, the proxy's relay, on the container runtime's bridge.

### Outbound

| From | To | When |
|---|---|---|
| workers | allow-listed destinations, usually TCP 443/80 | sandbox egress: the proxy runs on the worker, so traffic leaves from the worker's own IP. Perimeter rules key on worker IPs. |
| workers | DNS, UDP/TCP 53 | the proxy resolves allow-listed names on the worker; sandboxes have no resolver of their own |
| workers | your registry, TCP 443 | only when the guest image or a template's base image is not pre-loaded |
| control plane | your OTLP receiver | only if trace export is switched on |
| all | NTP | recommended: events carry the worker's clock |

### Worker address (`public_url`)

A multi-host worker must set `public_url` to the address clients and the control plane dial (`http://worker-1.example:7700`). Without it, the worker registers `127.0.0.1`.

### Host firewall examples

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

Docker writes its own iptables/nftables rules, but the rules above are still the whole picture:

- Qafas publishes no sandbox ports. Docker cannot publish from an internal network, and podman binds loopback only.
- The compose file uses host networking.

## 4. OS permissions

### The worker (`qafas`) runs as root

`qafas` runs as root under systemd, because it drives the container runtime's root socket, creates idmapped mounts, tap devices and nftables rules, and starts the Firecracker jailer. The unit narrows that:

- Capabilities (bounding set): `CAP_NET_ADMIN CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE`, plus `CAP_FOWNER CAP_MKNOD CAP_KILL` for the Firecracker jailer and for stopping microVMs. `/usr/lib/systemd/system/qafas.service` says which needs what.
- `ProtectSystem=full` (`/usr`, `/boot`, `/etc` read-only), `ProtectKernelModules`, `ProtectKernelLogs`, `RestrictRealtime`, `LockPersonality`.
- `NoNewPrivileges=no` and `ProtectHome=no` on purpose: the jailer changes uid, and workspaces live under `/home`.

### The container runtime's socket is root-equivalent

`/var/run/docker.sock` or `/run/podman/podman.sock` belongs to qafas alone. In the container install the `qafas` container holds it, so treat that container as root on the host.

### The control plane runs unprivileged

`controlplane` runs as the unprivileged `controlplane` user with no capabilities, `ProtectSystem=strict`, `ProtectHome=yes` and `PrivateDevices=yes`. It writes only `/var/lib/controlplane`.

### Sandboxes

- Sandboxes have an empty capability set, `no_new_privs`, a seccomp filter, a read-only root filesystem and no network but the proxy.
- What the boundary is depends on the tier and the host. `vm` on Linux is a container on the host's own kernel, not a VM, unless `SBX_VM_RUNTIME` names a sandboxing runtime (section 5.1); on macOS the container engine is a VM. Hostile code from several tenants belongs on a `remote` worker. [security.md](security.md) has the table.
- On podman and Firecracker they run as uid 1000, with the workspace mapped so that writes land as the directory's owner.
- On Docker, which has no idmapped mounts, they run as the workspace's owner directly, and a root-owned workspace is refused.
- Give each user a workspace they own (their home directory is the usual one).

### Files and directories

| Path | Mode | Holds |
|---|---|---|
| `/etc/controlplane/env` | 0640 root:controlplane | the three control-plane tokens, listen address, TLS paths |
| `/etc/qafas/qafas.toml` | 0640 root:root | the worker's token and host token, tiers, control-plane URL |
| `/etc/qafas/egress.json` | 0644 | the egress allowlist |
| `/var/lib/controlplane/` | controlplane | `sandbox.db` |
| `/var/lib/qafas/` | root | TLS pair, templates and their scans, the sandbox table, spooled events, the Firecracker bundle and jails |
| `/var/lib/qafas/egress-ca/` | 0700 root, `ca.key` 0600 | the egress CA, when `egress.json` has routes (section 7) |

## 5. Install methods

Pick one method for the control plane and the workers:

- [5.1 Packages](#51-packages-recommended), recommended.
- [5.2 Containers](#52-containers), from one compose file.
- [5.3 By hand, from the tarball](#53-by-hand-from-the-tarball).

Then, where it applies:

- [5.4 Firecracker workers](#54-firecracker-workers-remote-tier) turns a packaged worker into a `remote` (microVM) worker.
- [5.5 Native tier on a Linux developer machine](#55-native-tier-on-a-linux-developer-machine) sets up `native` on a developer's own Linux machine. It is not for production workers.

### 5.1 Packages (recommended)

Before you start, download `qafas-controlplane`, `qafas`, `qafas-cli` and `SHA256SUMS` as in the [README](../README.md) quick start, and check the sums. The README also sets `$A`, the package architecture the commands below use.

#### Server: on the control-plane host

1. Install the control-plane package.

   ```sh
   sudo apt install ./qafas-controlplane_$V-1_$A.deb             # or: sudo dnf install ./qafas-controlplane-$V-1.$A.rpm
   ```

2. Read the tokens the install minted. The workers need `SBX_HOST_TOKEN` and `SBX_TOKEN_SECRET`.

   ```sh
   sudo grep -E '^SBX_(ADMIN|HOST)_TOKEN|^SBX_TOKEN_SECRET' /etc/controlplane/env   # minted on install; keep them safe
   ```

#### Agents: on each worker

1. Install the worker package.

   ```sh
   sudo apt install ./qafas_$V-1_$A.deb                          # or: sudo dnf install ./qafas-$V-1.$A.rpm
   ```

2. Point the worker at the control plane.

   ```sh
   sudo editor /etc/qafas/qafas.toml
   ```

   ```toml
   cp_url     = "http://cp.example:7800"         # https://… once the control plane has TLS (section 6)
   host_token = "<SBX_HOST_TOKEN from the server>"
   token      = "<SBX_TOKEN_SECRET from the server>"
   public_url = "http://worker-1.example:7700"   # what clients and the control plane dial
   # ca_file  = "/etc/qafas/ca.crt"              # the CA an https cp_url chains to
   ```

3. Restart the worker so it registers with the new settings.

   ```sh
   sudo systemctl restart qafas
   ```

Verify: the control plane lists the worker, its tiers and its capacity.

```sh
curl -s -H "Authorization: Bearer $SBX_ADMIN_TOKEN" http://cp.example:7800/api/hosts   # the worker, its tiers and capacity
```

#### Clients

`qafas-cli` (Node.js 22) gives `sbx` and the TypeScript SDK. Or use the `sbx` container image.

#### Configuration reference

- Every key, with its default: `/usr/share/doc/qafas/qafas.toml.example`.
- Environment variables (`SBX_*`) override the file. The package pins the guest image that way (`/usr/lib/systemd/system/qafas.service.d/image.conf`), so it follows each upgrade.

#### Sandbox runtime on `vm` workers

`vm_runtime` in `/etc/qafas/qafas.toml` (or `SBX_VM_RUNTIME`) is the OCI runtime the `vm` tier's sandbox containers run under. Empty, the default, is the engine's own: `runc` on Docker, usually `crun` on podman, so on Linux a container on the host's kernel. Name a sandboxing runtime to put a user-space kernel (gVisor `runsc`) or a VM (Kata `kata`) between a sandbox and the host kernel. The egress proxy container always keeps the default runtime.

1. Install the runtime and register it with the engine. For gVisor on Docker, from a release of [gVisor](https://gvisor.dev/docs/user_guide/install/) (offline: carry its `runsc` and `containerd-shim-runsc-v1` in, like any other artifact):

   ```sh
   sudo install -m755 runsc containerd-shim-runsc-v1 /usr/local/bin/    # plus the gvisor-bin/ directory a release ships beside runsc
   sudo runsc install                                                  # adds "runsc" to "runtimes" in /etc/docker/daemon.json
   sudo systemctl restart docker
   ```

2. Set the name, restart `qafas`, and read the doctor line. The key goes at the top level, above any `[table]`; the packaged file takes an appended line.

   ```sh
   echo 'vm_runtime = "runsc"' | sudo tee -a /etc/qafas/qafas.toml
   sudo systemctl restart qafas
   sudo qafas doctor        # vm runtime   Docker 29.1.3: runsc: sandboxed (gVisor): ...
   ```

   With the container install, set `SBX_VM_RUNTIME` in `.env`; `compose.yml` passes it through (it passes only the variables it lists).

Verify: `qafas doctor` shows `vm runtime` with the name and `sandboxed (gVisor)` or `sandboxed (Kata)`; without the setting it shows `engine default` and `shared host kernel`. On macOS it says the engine is a VM.

Notes:

- The name must be one the engine has. Docker: a key of `"runtimes"` in `daemon.json` (`docker info` lists them). A name it does not know makes `qafas doctor` fail and `qafas serve` refuse to start, instead of running under the default.
- podman applies the per-container runtime only from 6.0. Before that, `doctor` fails with "ignores the create field oci_runtime": set the runtime as the engine's default in `/etc/containers/containers.conf` (under `[engine]`, `runtime = "runsc"`, and register the binary under `[engine.runtimes]` as `runsc = ["/usr/local/bin/runsc"]`; this changes every container on that engine, the proxy included) and leave `vm_runtime` empty. The line then reads `engine default, runsc`.
- gVisor was validated on Docker 29.1.3 (gVisor release-20261012.0, systrap, Ubuntu 24.04 aarch64): the template scan grades `base` A, `trust: untrusted` creates work, and the escape battery contains everything except one probe: a command can `kill -9 1` and end its own sandbox (gVisor does not give PID 1 the protection a kernel pid namespace does; a denial of service against itself, not an escape). [security.md](security.md) (Known gaps) has the details. Kata is untested.

### 5.2 Containers

The images `ghcr.io/exitcodenihil/qafas-sandbox/{controlplane,qafas,sbx}:$V` run from one compose file, per role: `deploy/docker/compose.yml` with `deploy/docker/.env.example`.

1. On the server, start the control plane.

   ```sh
   # server
   docker compose up -d controlplane
   ```

2. On each agent, give `.env` the same tokens plus the worker's own identity and addresses, then start `qafas`.

   ```sh
   # each agent: .env holds the same tokens, plus
   #   SBX_HOST_ID=worker-1  SBX_CP_URL=http://cp.example:7800  SBX_PUBLIC_URL=http://worker-1.example:7700
   docker compose up -d qafas
   ```

Verify: the `curl … /api/hosts` check at the end of section 5.1 lists the worker.

Notes:

- The `qafas` container serves the `vm` tier through the host's Docker (or podman: `CONTAINER_SOCK=/run/podman/podman.sock`). The sandboxes are ordinary host containers with the same boundary as the package install.
- Mount every directory people work in at the same path (`/home` and `/root` are there already).
- Mount your own `egress.json` over `/etc/qafas/egress.json`. Route secrets go in as compose secrets (section 7).
- The control plane's TLS pair mounts into its container (`SBX_TLS_CERT`, `SBX_TLS_KEY`; section 6).

### 5.3 By hand, from the tarball

`qafas-$V-linux-<arch>.tar.gz` holds `bin/{qafas,guest-agent,controlplane}` and `deploy/` (the systemd units, `env.example`, `qafas.toml`). Run these steps from the extracted directory.

1. Install the binaries.

   ```sh
   sudo install -m755 bin/qafas bin/controlplane /usr/bin/
   ```

2. Create the unprivileged user the control plane runs as.

   ```sh
   sudo useradd --system --home /var/lib/controlplane --shell /usr/sbin/nologin controlplane
   ```

3. Install the configuration files, then fill in the tokens in `/etc/controlplane/env`.

   ```sh
   sudo install -Dm640 -g controlplane deploy/controlplane/env.example /etc/controlplane/env     # fill in the tokens
   sudo install -Dm640 deploy/qafas.toml /etc/qafas/qafas.toml                                   # the full reference
   ```

4. Install the systemd units.

   ```sh
   sudo install -m644 deploy/systemd/qafas.service deploy/controlplane/controlplane.service /etc/systemd/system/
   ```

5. Pin the guest image to this version, as the package does. The guest image and the daemon must be the same version: the egress proxy runs the `qafas` binary from inside that image.

   ```sh
   printf '[Service]\nEnvironment=SBX_TEMPLATE_IMAGE=ghcr.io/exitcodenihil/qafas-sandbox/sbx-base:%s\n' $V |
     sudo install -Dm644 /dev/stdin /etc/systemd/system/qafas.service.d/image.conf
   ```

6. Start both services.

   ```sh
   sudo systemctl daemon-reload && sudo systemctl enable --now controlplane qafas
   ```

Verify: the `curl … /api/hosts` check at the end of section 5.1 lists the worker.

### 5.4 Firecracker workers (`remote` tier)

The release ships `qafas-firecracker-$V-<x86_64|aarch64>.tar.zst`: Firecracker and its jailer, a guest kernel, the guest root filesystem built from this release's image, and the guest agent, laid out against `/`.

Before you start, check the `remote` worker requirements in section 2 (`/dev/kvm`, cgroup v2, nftables, iproute2, e2fsprogs).

1. Install the worker package, as in 5.1, with the tools the `remote` tier uses.

   ```sh
   sudo apt install ./qafas_$V-1_$A.deb nftables iproute2 e2fsprogs   # the worker package, as in 5.1
   ```

2. Extract the bundle onto `/`. Keep `-m`: on upgrade the new files get the current time, which tells qafas to recapture `base`.

   ```sh
   sudo tar --zstd -xpmf qafas-firecracker-$V-$(uname -m).tar.zst -C /
   ```

3. Check that KVM and Firecracker are usable.

   ```sh
   ls /dev/kvm && sudo /usr/bin/qafas doctor                           # kvm and firecracker: ok
   ```

4. Switch the worker to the `remote` tier and restart it.

   ```sh
   sudo sed -i 's/^tiers .*/tiers      = ["remote"]/' /etc/qafas/qafas.toml
   sudo systemctl restart qafas
   ```

Verify: the log shows the base capture, then the pool fills.

```sh
sudo journalctl -u qafas -n 30 --no-pager                           # "base memory snapshot captured", then the pool fills
```

#### Firecracker settings

- The packaged config already points `[firecracker]` at the bundle and keeps the jail at `/var/lib/qafas/jail`, on the same filesystem as the templates, so disks and memory captures are hard links rather than copies.
- `[firecracker] mem_mib` (default 2048) is every guest's RAM. Raise it to 4096 to serve `high`.
- Every template is a memory capture, so a create is a restore (tens of milliseconds pooled, about a second cold) rather than a boot.
- Huge pages (`hugepages = true`) speed up nested virtualisation but rule out captures, stop/start and archives. Leave them off unless you know you want that trade.
- The bundled kernel has no BTF, so in-guest process telemetry samples `/proc` every 25 ms instead of using eBPF. For eBPF, build a guest kernel from Firecracker's `microvm-kernel-ci-<arch>-6.1.config` with `DEBUG_INFO_BTF`, `BPF_SYSCALL`, `BPF_EVENTS`, `FTRACE_SYSCALLS`, `OVERLAY_FS` on and `FUNCTION_TRACER` off, and point `[firecracker] kernel` at it.

#### Host hardening

A microVM boundary is only as good as the host under it. On a worker that runs untrusted code from more than one party:

- Turn simultaneous multithreading off (`nosmt` on the kernel command line, or `echo off > /sys/devices/system/cpu/smt/control`). This closes cross-guest side channels between sibling threads.
- Turn kernel samepage merging off (`echo 0 > /sys/kernel/mm/ksm/run`) and run without swap, so one guest's memory is never shared with or written out beside another's.
- Keep the host kernel and microcode current.
- On a cloud VM, set the instance metadata service to IMDSv2 with a hop limit of 1, so nothing forwarded from the host can reach it (sandboxes already cannot: link-local is always denied).

### 5.5 Native tier on a Linux developer machine

`native` is an OS process sandbox. It runs commands as the daemon's own user, so it belongs only on a trusted developer machine, never on a root-run worker, and `trust: untrusted` never resolves to it. On macOS it needs macOS 14+ and uses Seatbelt (`/usr/bin/sandbox-exec`). This section covers Linux.

Requirements on Linux:

- `bwrap` (bubblewrap) on `PATH`.
- Landlock in the kernel, ABI 2 or later, for the filesystem rules. The network is confined by the sandbox's own network namespace.
- `qafas` running as the developer's own user, never as root. A root daemon, such as the systemd service in section 4, does not serve `native`: `qafas doctor` shows `native user` FAIL with the reason.

Check the host as the user who will run `qafas`. The `bubblewrap`, `landlock`, `native user` and `bwrap sandbox` lines are the ones `native` needs.

```sh
qafas doctor
```

#### Ubuntu 24.04 and later: allow bwrap to create user namespaces

These releases restrict unprivileged user namespaces with AppArmor (`kernel.apparmor_restrict_unprivileged_userns = 1`). `bwrap` then fails with `bwrap: setting up uid map: Permission denied`, and `qafas doctor` shows `bwrap sandbox` FAIL with that hint. An AppArmor profile that lets `bwrap` create user namespaces fixes it:

```sh
sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/bwrap
qafas doctor        # "bwrap sandbox  starts as this user"
```

Verify: `qafas doctor` shows `bwrap sandbox  starts as this user`.

#### What a Linux native sandbox gets

- The system is read-only.
- `/home`, `/root` and `/run` are replaced by empty tmpfs, so the user's credentials and the podman, Docker and D-Bus sockets are not visible. The user's toolchain directories (for example `~/.cargo`, `~/.rustup`, `~/.nvm`, `~/.pyenv`, `go/pkg/mod`) are bound back read-only.
- Credential paths (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`) are covered, even inside the workspace.
- Writes go only to the workspace and the sandbox's scratch directory.
- A network namespace of its own with only `lo`: no address outside the sandbox is reachable. The egress proxy appears inside at the address in `HTTPS_PROXY` (`127.0.0.1:<port>`), relayed through a unix socket in the sandbox's scratch directory to the sandbox's own proxy on the host. `qafas doctor`'s `bwrap sandbox` line checks that bwrap can create the namespace.
- Every command runs under Landlock (filesystem) plus the same seccomp deny-list the `vm` tier uses. Seccomp also refuses IPv4 and IPv6 sockets other than TCP (UDP, raw, SCTP, MPTCP), as are TCP Fast Open sends.
- Private pid, uts and ipc namespaces.
- The sandbox dies with the daemon.

Its own loopback is the sandbox's: a command may listen on any port and another command in the same sandbox may connect to it (a test suite with a local server, `curl localhost:PORT`, a browser against a dev server). Nothing outside can reach that namespace, so the host cannot reach such a server on `localhost:PORT`; reach it from outside through a preview URL, as on the other tiers: `POST /sandboxes/{id}/preview` with `{"port": PORT}` returns a URL and a token (protocol §3a). On macOS the server listens on the host's loopback and is reachable there as well.

The adversarial escape battery (`make escape TIER=native`, 21 probes) passes on Ubuntu 24.04 arm64: every probe contained and alerted.

## 6. Tokens and TLS

### Tokens

| Secret | Set on | Presented by | To | For |
|---|---|---|---|---|
| `SBX_ADMIN_TOKEN` | control plane | people, the CLI, admin scripts | control plane | everything |
| API keys | dashboard → API keys | agents, SDKs (`SBX_API_KEY`) | control plane | their own sandboxes, within the sizes and tiers the key allows |
| `SBX_HOST_TOKEN` = worker `host_token` | both | workers (and Prometheus) | control plane | registering and reporting |
| `SBX_TOKEN_SECRET` = worker `token` | both | control plane | workers | administering a worker; the worker signs per-sandbox tokens with it |
| per-sandbox token | minted by the worker | clients | that worker, that sandbox only | 12 hours (`token_ttl_secs`) |

- Whoever holds `SBX_HOST_TOKEN` can register a worker under any name: treat it like the admin token.
- To rotate a token, change it on both sides and restart both services.

### TLS on the control plane

1. Put a certificate and key from your CA on the server, readable by the `controlplane` group.
2. Add both paths to `/etc/controlplane/env`, then restart the control plane:

   ```sh
   SBX_TLS_CERT=/etc/controlplane/tls.crt
   SBX_TLS_KEY=/etc/controlplane/tls.key
   ```

3. On each worker, set `cp_url = "https://cp.example:7800"` and `ca_file` (or put the CA in the system bundle).
4. Clients trust the same CA: the CLI and the SDKs through `SBX_CA_FILE` (Node also honours `NODE_EXTRA_CA_CERTS`), browsers through the OS trust store.

### TLS on workers

`tls = true` in `qafas.toml` serves the worker API, WebSockets included, over HTTPS. Choose where the certificate comes from:

| Certificate | How it is trusted |
|---|---|
| From your CA (recommended): `tls_cert` / `tls_key`, plus `SBX_CA_FILE` on the control plane pointing at that CA | every hop is verified against the CA |
| Self-signed: no `tls_cert` / `tls_key` | the worker generates a pair once into `/var/lib/qafas/tls`, and the control plane pins its fingerprint at registration (trust on first use, guarded by `SBX_HOST_TOKEN`). Clients receive the pin with each sandbox and verify against it. |

- The certificate's names must include what `public_url` says.
- To check a pin by hand: `openssl x509 -in /var/lib/qafas/tls/cert.pem -noout -fingerprint -sha256`.

## 7. Egress

Every sandbox's only way out is the proxy on its worker. The proxy reads `/etc/qafas/egress.json` at start, so restart `qafas` after editing it.

```json
{
  "allow": ["github.com", "*.github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"],
  "deny_cidrs_extra": ["203.0.113.0/24"],
  "allow_private_cidrs": []
}
```

- A destination must match an `allow` glob and resolve to a public address. Loopback, private ranges, link-local (so `169.254.169.254`), CGNAT and multicast are refused whatever `allow` says.
- Internal mirrors: list their private range in `allow_private_cidrs` and their names in `allow`, for example `"allow": ["nexus.corp.example"], "allow_private_cidrs": ["10.20.0.0/16"]`. Only RFC1918 and IPv6 unique-local ranges can be opened; loopback, link-local and CGNAT stay shut.
- A harness may add names for one sandbox (`egress_allow` on create; an API key can limit which names its holder may add). It can never add ranges. The model inside the sandbox can change nothing.
- Every refusal is an `egress.deny` event. Probes of metadata endpoints raise alerts on the dashboard's Alerts page.

### Routes: credentials and per-request rules

A route lets a sandbox use a credential it never holds ([D34](decisions.md#d34--credentials-are-attached-at-the-egress-proxy-for-bound-hosts-only-2026-10-20)). The sandbox gets a placeholder in an environment variable; the proxy terminates TLS for the route's hosts, swaps the placeholder for the real secret, checks each request against the route's rules, and removes the secret from every response. The full field list is in [protocol.md §6](protocol.md#routes-v54-d34).

```json
{
  "allow": ["pypi.org", "files.pythonhosted.org"],
  "routes": [
    {
      "name": "github",
      "hosts": ["github.com", "api.github.com"],
      "secret": "file:///etc/qafas/secrets/github.token",
      "env": "GITHUB_TOKEN",
      "inject": { "header": "Authorization", "format": "Bearer {secret}" },
      "rules": [{ "methods": ["GET", "POST"], "paths": ["/acme/*", "/repos/acme/*"] }]
    }
  ]
}
```

- **Secrets** are references: `env://NAME` (the `qafas` process's environment) or `file:///abs/path` (`chmod 600`, owned by the user `qafas` runs as). They are read once at start; edit and restart. A route whose secret cannot be read stops `qafas` from starting, and `qafas doctor` names it (`egress routes … FAIL`). The value never appears in a log, an event, an API reply or what the worker reports to the control plane.
- **Who gets it:** sandboxes whose trust the route lists, `trusted` by default. They see `GITHUB_TOKEN=qafas_ph_github_<24 hex>`. For them every connection to `github.com:443` is intercepted, and `github.com` on any other port or over plain HTTP is refused. An untrusted sandbox gets no placeholder; for it `github.com` is an ordinary name, reachable only if `allow` lists it, and then without the credential.
- **Hosts:** list exact names. A glob that covers names other people control (`*.s3.amazonaws.com`, `*.github.io`) sends them the secret.
- **Clients:** the sandbox's `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `CARGO_HTTP_CAINFO` and `PIP_CERT` point at a bundle with the system roots plus the egress CA, `NODE_EXTRA_CA_CERTS` at the CA alone, and Chromium trusts it by key hash. Java trust stores are not configured. HTTP/1.1 only.
- **git:** git sends credentials only after a 401, so either give the route an `inject` header, or hand git the placeholder through a credential helper:

  ```sh
  git -c credential.helper='!f(){ echo username=x-access-token; echo password=$GITHUB_TOKEN; }; f' clone https://github.com/acme/app.git
  ```

- **Internal hosts with an internal CA:** set `SBX_EGRESS_CA_FILE` (config key `egress_ca_file`) to that CA's PEM. Route hosts are verified against the system roots plus that file. A route host on a private address still needs its range in `allow_private_cidrs`.
- **The CA** lives in `<state_dir>/egress-ca/` (`/var/lib/qafas/egress-ca/` for the packages): `ca.pem`, and `ca.key` mode `0600`. It is made on the first start with routes and kept, so placeholders and every sandbox's trust survive restarts. To rotate it, delete the directory and restart `qafas`; running sandboxes keep the old placeholders, so recreate them. Warm pools need nothing: placeholders and the CA are handed over when a sandbox is acquired.
- **Native tier:** the sandbox runs as the daemon's own user, so keep a `file://` secret where that tier cannot read. `~/.qafas`, the default state directory of a non-root daemon (it holds the CA key), is hidden from native sandboxes by default, so a workspace of `$HOME` does not expose it; a state directory or secret anywhere else is safe only if the workspace does not contain it. Not `/etc`: both Seatbelt and bwrap let a native sandbox read it.
- **Containers (section 5.2):** pass the secret as a compose secret and point the route at it:

  ```yaml
  # compose.yml, qafas service
  services:
    qafas:
      secrets: [github_token]
      volumes:
        - ./egress.json:/etc/qafas/egress.json:ro
  secrets:
    github_token:
      file: ./github.token   # chmod 600
  ```

  Compose bind-mounts the file with the host's permissions (`mode:` is ignored outside swarm), and `qafas` refuses a secret file that is group- or world-readable, so `chmod 600` the host file. In `egress.json`: `"secret": "file:///run/secrets/github_token"`. For `SBX_EGRESS_CA_FILE`, mount the PEM into the container and set the variable to its path there. The worker hands the routes, their secrets and the CA to its proxy container in one environment variable (`SBX_ROUTES_JSON`), so anyone who can inspect containers on that host can read them: the same people who can read the secret file.
- **What is checked at start** (`serve` and `doctor` refuse a bad route, naming it, never a value): the name is `[a-z0-9_-]+` and unique; `hosts` is not all wildcards (`*`, `*.*`); `ports` and `trust` are non-empty and no port is 0; `env` is a valid variable name, unique across routes, not a protected name (`HOME`, `PATH`, the proxy variables, anything starting `LD_` or `DYLD_`) and not one of the CA variables, and it needs `secret` and the other way round; the secret is at least 8 printable ASCII characters; `inject.format` contains `{secret}` and `inject.header` is not a framing or hop-by-hop header (`Host`, `Content-Length`, `Transfer-Encoding`, …); a rule's `paths` start with `/` or `*`, its methods are letters. A path glob's `*` matches across `/`.
- **`qafas doctor` reads `env://` secrets from its own shell**, not from the service's environment: under systemd run it with the service's variables (`sudo systemctl show qafas -p Environment`, or `sudo env NAME=… qafas doctor`), or it reports a missing secret for a service that is fine.
- **Operational facts:** upstream certificates are verified against the first of `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem` that exists on the worker plus `SBX_EGRESS_CA_FILE`; with none of them every route host fails `upstream tls failed`. The upstream connect and handshake time out at 30 s. The proxy container's peer lookup waits 2 s and then fails closed to the host file. The CA is valid for about ten years (delete the directory to renew it). Leaf certificates are cached for 12 hours, 256 at most. On a route with a secret, the end of each response chunk is held back until the next chunk (so a secret split across two is still found), which delays a tiny server-sent event until the next one or the end of the response.
- **Events:** each request on a route is one `egress.allow` or `egress.deny` with `method`, `path` (no query), `route` and `injected`. A rule miss is `reason: "l7 rule"`.

## 8. Operations

### Upgrades

1. On a worker that cannot pull, load the new guest image first ([airgap.md](airgap.md)). The new package pins it, and a worker whose image is missing does not start.
2. Upgrade the control plane, then the workers, with the same `apt`/`dnf install` command and the new files. Database migrations run forward on start. Your edited config files are kept:
   - apt asks when the packaged default changed too. Keep yours (`N`; unattended, `apt-get -o Dpkg::Options::=--force-confold install …`) and compare it with the new default it leaves beside it (`qafas.toml.dpkg-dist`).
   - dnf keeps yours without asking and writes `.rpmnew`.
3. On Firecracker workers, extract the new bundle with `tar -m` before restarting `qafas`. The `base` capture is redone automatically.
4. Rebuild your own templates after an upgrade (dashboard → Templates → delete and recreate, or the API): they carry the guest agent from when they were built. A template built before 0.4 has no `POST /ca`: with routes configured its sandboxes log a warning and TLS to a route host fails closed until the template is rebuilt.
5. Running `vm` and `native` sandboxes that were adopted from before 0.4 come back as untrusted and without their `egress_allow` (the live table gained those fields), so they get no route placeholders and no interception until they are recreated.

A worker restart destroys its running `vm` sandboxes; `remote` sandboxes are paused to disk and resumed.

### Backups

Control plane: back up the database (safe while running) and `/etc/controlplane/env`.

```sh
sudo sqlite3 /var/lib/controlplane/sandbox.db ".backup '/backup/sandbox-$(date +%F).db'"
```

To restore: stop the service, put the file back, start it. Workers re-register by themselves.

Workers: back up `/etc/qafas/`, `/var/lib/qafas/tls/` (its pinned certificate) and, with routes, `/var/lib/qafas/egress-ca/` (keep it as private as the secrets). Templates can be rebuilt; the rest is per-sandbox state.

### Monitoring

- Metrics: the control plane serves `GET /metrics` (`sbxcp_*`) and `GET /api/prometheus/targets`, a service-discovery list that routes every worker's metrics (`sbx_*`) through the control plane, so Prometheus needs no route to the workers. Authenticate with `SBX_HOST_TOKEN` or the admin token.
- Ready-made stack: `deploy/monitoring/` holds Prometheus, Alertmanager, Grafana (fleet, security and control-plane dashboards), Jaeger and node-exporter. Run `cp .env.example .env`, set the token, then `make monitoring-up`. It scrapes the control plane on the same machine; for another machine, edit the two addresses in `prometheus.yml`.
- Traces: the dashboard's Settings → Observability pushes OTLP/HTTP to a receiver you run (Jaeger, Tempo, Langfuse self-hosted).

### Troubleshooting

| Symptom | Look at |
|---|---|
| a worker is missing from Hosts | `journalctl -u qafas` for "host register failed": `cp_url`, `host_token`, the firewall on 7800, and `ca_file` for an https control plane |
| it is listed, but sandboxes fail to start | `public_url` is reachable from the control plane and the clients on 7700 |
| `no tier available on this host` | `sudo qafas doctor`: the runtime socket, `/dev/kvm`, the Firecracker files |
| `Docker Engine … is too old` | upgrade to Docker 26 or later |
| `vm runtime: … does not know the runtime …` (doctor FAIL, `serve` refuses) | register the runtime in `daemon.json` under `"runtimes"` and restart Docker, or fix `vm_runtime` (section 5.1) |
| `vm runtime: podman … ignores the create field oci_runtime` | podman before 6.0 cannot run one container under another runtime: set it as the engine default in `containers.conf` and leave `vm_runtime` empty (section 5.1) |
| `… is owned by root` / `… does not exist; on the Docker runtime …` | run from an existing directory a regular user owns |
| `pull …: …` on first start | the guest image is not loaded and the registry is unreachable: load it ([airgap.md](airgap.md)) |
| a changed `pool_size` has no effect | an earlier `PUT /snapshots/base {warm}` is kept in `/var/lib/qafas/snapshots/base.warm` and wins (the log says so at start): delete the file, or `PUT` the new number |
| `mem_mib … exceeds this host's template RAM` | raise `[firecracker] mem_mib`, or ask for a smaller size |
| `template … failed its security scan` | an untrusted sandbox asked for an F-graded template: open it under Templates to see why |
| `egress route "…": secret … is not set` / `… is readable by group or others` (doctor FAIL, `serve` refuses) | set the variable in the `qafas` service's environment, or `chmod 600` the file (section 7) |
| a route host answers `502` with `egress.deny` `upstream tls failed` | the host's certificate does not chain to the system roots: put its CA in `SBX_EGRESS_CA_FILE` (section 7) |
| a client in the sandbox rejects a route host's certificate | it ignores the CA variables (a Java client, a pinned certificate): point it at `$SSL_CERT_FILE` |
| `qafas doctor`: `native user` FAIL | the daemon runs as root, and a root daemon does not serve `native`: run `qafas` as the developer's own user (section 5.5) |
| `qafas doctor`: `bwrap sandbox` FAIL, `bwrap: setting up uid map: Permission denied` | AppArmor restricts unprivileged user namespaces (Ubuntu 24.04 and later): add the `bwrap` profile in section 5.5 |

### Known limits

- One control plane, SQLite, no high availability: keep backups.
- A worker serves one pooled runtime.
- The Firecracker `/30` range and the 126-microVM limit are fixed in this release.
- Template pulls on Docker are anonymous: pre-load private base images, or use a registry that allows anonymous pulls on the internal network.
