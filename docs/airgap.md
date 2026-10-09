# Air-gapped installation

Installing Qafas Sandbox in a datacenter with no route to the internet, where the VMs may also be micro-segmented from each other. Nothing in Qafas phones home: once the artifacts are inside, the control plane, the workers, the sandboxes and the Firecracker microVMs reach nothing you did not open. Read [deployment.md](deployment.md) first — roles, sizing, ports and permissions are the same; this page is about getting the bits in and the network rules between segments.

It takes four steps:

1. **Stage** the release on a connected machine and carry it in.
2. **Load the images**, from a tarball on each host or through your private registry.
3. **Install** the server, then the agents.
4. **Open** the few flows the segments need, and verify nothing else leaves.

```sh
V=0.1.0      # the release being installed  (x-release-please-version)
```

## 1. Stage the artifacts

On a machine with internet access, collect what each role needs. Do not run any of these downloads on the offline hosts.

| role | release assets | from your OS mirror (or staged, below) |
|---|---|---|
| control plane | `qafas-controlplane` deb/rpm | — |
| `vm` worker | `qafas` deb/rpm, and the images (below) | Docker Engine 26+ **or** podman 4.4+ |
| Firecracker worker | `qafas` deb/rpm, `qafas-firecracker-$V-<x86_64\|aarch64>.tar.zst`, and the images (template builds) | podman, nftables, iproute2, e2fsprogs |
| clients | `qafas-cli` deb/rpm, or the `sbx` image | Node.js 22 |
| container install (instead of packages) | the images | Docker Engine 26+ |
| every role | `SHA256SUMS`, `images.txt`, `qafas-save-images.sh`, `qafas-load-images.sh` | — |

Every release publishes **`images.txt`** — each image that version runs, pinned (`ghcr.io/exitcodenihil/qafas-sandbox/{sbx-base,controlplane,qafas,sbx}:$V`) — and two scripts: `qafas-save-images.sh` pulls that list into one tarball, `qafas-load-images.sh` loads it inside and, given a registry, pushes it there. The newest list is always at `https://github.com/exitCodeNihil/qafas-sandbox/releases/latest/download/images.txt`.

```sh
mkdir qafas-$V && cd qafas-$V
gh release download v$V -R exitCodeNihil/qafas-sandbox \
  -p 'qafas*.deb' -p 'qafas*.rpm' -p 'qafas-firecracker-*.tar.zst' \
  -p images.txt -p 'qafas-*-images.sh' -p SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS

# Every image, for the architecture your hosts run (docker or podman; one run per architecture)
./qafas-save-images.sh --platform linux/amd64          # writes qafas-images-amd64.tar.gz
```

Keep only the architectures you run. The images come to about 550 MB compressed per architecture (most of it the guest image); the Firecracker bundle is about 350 MB. Registries that need a login: `docker login ghcr.io` (or `podman login`) before saving. The guest image alone is also a release asset, `sbx-base-$V-<arm64|amd64>.tar.zst` (`zstd -dc … | podman load`).

**OS packages.** Most datacenters have an internal apt/dnf mirror; use it. Otherwise download the runtime with its dependencies on a connected machine running the **same OS release** as the targets:

```sh
# Ubuntu / Mint
sudo apt-get install --download-only -y podman nftables iproute2 e2fsprogs   # or docker.io docker-compose-v2
cp /var/cache/apt/archives/*.deb ./os-debs/
# RHEL / Rocky
dnf download --resolve --alldeps --destdir ./os-rpms podman nftables iproute e2fsprogs
```

Carry the directory in (removable media, a data diode, a transfer host) and check it again on the inside: `sha256sum -c SHA256SUMS`.

## 2. Load the images

Every `vm` worker needs the guest image `ghcr.io/exitcodenihil/qafas-sandbox/sbx-base:$V`; the package pins exactly that name and version, and a worker whose image is missing stops at start rather than run something else. Templates need whatever their `FROM` names. Pick one method.

### Method A — a tarball on each host

No registry needed; right for small fleets and edge sites. On each host:

```sh
sudo ./qafas-load-images.sh --images qafas-images-amd64.tar.gz      # into podman, or docker where there is no podman
sudo podman images | grep qafas-sandbox                            # sbx-base, controlplane, qafas, sbx   $V
```

The images keep the names the package pins, so nothing else changes — this covers the container install too.

### Method B — your private registry

Harbor, Artifactory, Nexus, GitLab, or a plain `registry:2`. Push once from any host inside that has docker or podman and can reach the registry (`docker login` / `podman login` first if it asks for credentials):

```sh
REG=registry.corp.example:5000
./qafas-load-images.sh --images qafas-images-amd64.tar.gz --registry $REG
# podman, to a registry without a trusted certificate: CONTAINER_CLI=podman … --tls-verify=false
```

Each image keeps its path under the new host: `ghcr.io/exitcodenihil/qafas-sandbox/sbx-base:$V` becomes `$REG/exitcodenihil/qafas-sandbox/sbx-base:$V`. One architecture per registry path: a mixed fleet pushes each architecture's tarball under its own path, or copies the multi-arch images with `skopeo copy --all` from a connected machine. Then point the workers at it — by name, as the script prints at the end, or by mirroring the public name:

```sh
# By name (works for Docker and podman): an override that sorts after the package's image.conf
sudo mkdir -p /etc/systemd/system/qafas.service.d
printf '[Service]\nEnvironment=SBX_TEMPLATE_IMAGE=%s/exitcodenihil/qafas-sandbox/sbx-base:%s\n' "$REG" "$V" |
  sudo tee /etc/systemd/system/qafas.service.d/registry.conf
# (container install: set SBX_TEMPLATE_IMAGE under the qafas service's environment in compose.yml,
#  and the two images: lines to $REG/exitcodenihil/qafas-sandbox/…)
```

```toml
# podman only, by mirror — /etc/containers/registries.conf.d/qafas.conf: pulls of ghcr.io names
# come from your registry, so upgrades need no edit here
[[registry]]
prefix   = "ghcr.io/exitcodenihil"
location = "registry.corp.example:5000/exitcodenihil"
```

Registry trust and credentials:

- Give the registry a certificate from your CA and install the CA on each worker: `/etc/containers/certs.d/$REG/ca.crt` (podman) or `/etc/docker/certs.d/$REG/ca.crt` (Docker). `insecure = true` in `registries.conf` / `insecure-registries` in `/etc/docker/daemon.json` work too, at the obvious cost.
- podman: `sudo podman login $REG` once on each worker; qafas pulls as root, through the same credentials.
- Docker: qafas pulls anonymously (Docker keeps credentials in its client, not the daemon). Either allow anonymous pulls from the worker segment, or pre-pull on each worker with `sudo docker pull …` after `docker login` — a present image is never pulled again.

**Templates offline.** A template is built on each worker by its container runtime, so its `FROM` must name an image the worker can get: `FROM registry.corp.example:5000/library/python:3.12-slim`, or one already loaded. `RUN apt-get` / `pip install` steps inside a template build use the worker's network (not a sandbox's egress proxy), so point them at your mirrors in the Dockerfile. Bake mirror settings for the sandboxes in at the same time:

```dockerfile
FROM registry.corp.example:5000/exitcodenihil/qafas-sandbox/sbx-base:<version>
ENV PIP_INDEX_URL=https://nexus.corp.example/repository/pypi/simple \
    UV_INDEX_URL=https://nexus.corp.example/repository/pypi/simple \
    npm_config_registry=https://nexus.corp.example/repository/npm/
```

## 3. Install

**Server** (no dependencies):

```sh
sudo apt install ./qafas-controlplane_$V-1_amd64.deb     # or: sudo dnf install ./qafas-controlplane-$V-1.x86_64.rpm
```

Give it a certificate from your CA (`SBX_TLS_CERT`, `SBX_TLS_KEY` in `/etc/controlplane/env`; deployment.md section 6), then restart it.

**`vm` agents.** Install the container runtime first (from your mirror or `./os-debs`), load the images (Method A) or add the registry override (Method B), then the worker package:

```sh
sudo apt install ./os-debs/*.deb                     # or: sudo dnf install ./os-rpms/*.rpm
sudo ./qafas-load-images.sh --images qafas-images-amd64.tar.gz
sudo apt install ./qafas_$V-1_amd64.deb
sudo editor /etc/qafas/qafas.toml                    # cp_url, host_token, token, public_url, ca_file — deployment.md 5.1
sudo systemctl restart qafas
```

`apt`/`dnf` resolve the package's runtime dependency against what is already installed, so nothing is fetched.

**Firecracker agents.** The same, plus the bundle; nothing is downloaded at install or at run time:

```sh
sudo apt install ./os-debs/*.deb ./qafas_$V-1_amd64.deb
sudo tar --zstd -xpmf qafas-firecracker-$V-x86_64.tar.zst -C /
sudo sed -i 's/^tiers .*/tiers      = ["remote"]/' /etc/qafas/qafas.toml   # plus cp_url, tokens, public_url
sudo systemctl restart qafas
```

**Clients:** `qafas-cli` with Node.js 22 from your mirror, or the `sbx` image (loaded with the others) and the alias from the README.

**Container install** instead of packages: load the images (Method A — with `CONTAINER_CLI=docker` if the host also has podman — or B and edit the `image:` lines), copy `deploy/docker/compose.yml` and `.env.example` in with the release, and follow deployment.md section 5.2.

## 4. Micro-segmentation

Qafas needs very few flows, and every one has a fixed direction. Open these between segments and nothing else:

| from | to | port | purpose | needed |
|---|---|---|---|---|
| clients | control plane | 7800/tcp | API, dashboard | always |
| clients | every worker | 7700/tcp | exec, files, shell, browser — the data path does not go through the control plane | always |
| workers | control plane | 7800/tcp | registration, heartbeats, events | always |
| control plane | every worker | 7700/tcp | create, destroy, metrics, previews | always |
| workers | registry | 443 or 5000/tcp | Method B, and templates whose base image is not loaded | if used |
| workers | package mirrors | 443/80/tcp | sandbox egress to allow-listed mirrors, and template `RUN` steps | if used |
| workers | DNS | 53 | resolving allow-listed names and registry names (all of Qafas also works by IP) | if names are used |
| monitoring | control plane | 7800/tcp | Prometheus; it never needs the workers | optional |
| control plane | trace receiver | its port | OTLP push | optional |
| all | NTP | 123/udp | event timestamps come from worker clocks | recommended |

Never needed: worker ↔ worker, anything ↔ the internet, and any flow **to** a sandbox. Sandboxes have no address on your network: a `vm` sandbox sits on an internal container network with no exit but the proxy, a microVM on a `/30` tap that only reaches the proxy.

All sandbox traffic leaves from the **worker's own IP**, through its egress proxy, and only to names in `/etc/qafas/egress.json`. To let sandboxes use an internal mirror, allow it at both ends:

```json
{
  "allow": ["nexus.corp.example", "*.pkg.corp.example"],
  "allow_private_cidrs": ["10.20.0.0/16"]
}
```

- `allow_private_cidrs` is needed because an air-gapped mirror has a private address, which the proxy otherwise refuses; only RFC1918 and IPv6 unique-local ranges can be opened, never loopback, link-local or CGNAT.
- On the mirror's side, allow the worker IPs — not a sandbox range.
- Restart `qafas` after changing the file.

If the segments use a stateful firewall per VM (NSX, Calico host endpoints, nftables), express the rules by worker and control-plane IPs. A worker's own container networks (`10.89.x.0/24` on podman, Docker's pools) and the microVM range (`172.16.1.0`–`172.16.126.255`) never appear on the wire, but must not overlap ranges the worker routes to (deployment.md, Address ranges).

## 5. Verify nothing leaves

With the fleet up, run a sandbox that uses the network, and watch everything leaving a worker that is not part of your expected flows:

```sh
sbx run -- 'curl -s -o /dev/null -w "%{http_code}\n" https://nexus.corp.example/; curl -s https://example.com || echo refused'
sudo tcpdump -ni any 'not host 10.0.1.5 and not net 10.20.0.0/16 and not port 22 and not port 53'   # your CP, mirrors, admin, DNS
sudo ss -tnp | grep -E 'qafas|firecracker|controlplane'
```

Expect silence from `qafas`, the control plane, the guest agent, Firecracker and the jailer. In a rehearsal of this page (Ubuntu 24.04, podman, every packet to the internet dropped and logged), the only attempts were the OS's own NTP client (point it at your NTP server), IPv6 link-local multicast on the container bridges, and the egress proxy carrying a test sandbox's request to an allow-listed public site — exactly the flow `egress.json` permits, and the one to close by listing only internal names there.

## 6. Upgrades offline

1. Stage and verify the new release as in step 1: its `images.txt`, then `qafas-save-images.sh`.
2. Get the new images onto every `vm` worker first — `qafas-load-images.sh` on each (Method A), or once with `--registry` and bump the version in `registry.conf` (Method B; the mirror form needs no edit). A worker upgraded before its image is present stops at start until it is.
3. Upgrade the control plane, then the workers: the same `apt`/`dnf install ./…` with the new files. Keep your edited `qafas.toml` when apt asks (deployment.md, Upgrades).
4. Firecracker workers: extract the new bundle with `tar -xpm` (the fresh timestamps make qafas recapture `base`), then restart `qafas`.
5. Rebuild your own templates; they carry the guest agent of the release that built them.
