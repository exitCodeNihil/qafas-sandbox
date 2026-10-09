#!/usr/bin/env bash
# Redeploys the remote tier into the sbx-kvm Lima VM after `make image` and
# `podman save localhost/sbx-base:dev -o images/out/sbx-base.tar` on the Mac
# (the Firecracker test VM; docs/deployment.md 5.4). Run on the Mac: bash images/redeploy-lima.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
limactl copy "$REPO/target/aarch64-unknown-linux-musl/release/qafas" sbx-kvm:/tmp/qafas.new
limactl copy "$REPO/target/aarch64-unknown-linux-musl/release/guest-agent" sbx-kvm:/tmp/guest-agent.new
limactl shell sbx-kvm -- sudo bash -c "
set -e
podman load -i '$REPO/images/out/sbx-base.tar' >/dev/null
# The repo mount is read-only inside Lima; /opt/sbx/images is the VM's own copy
# (its out/vmlinux is the BTF kernel, which build-rootfs.sh keeps when present).
install -m755 '$REPO/images/build-rootfs.sh' /opt/sbx/images/build-rootfs.sh
SBX_ROOTFS_SIZE_MB=2048 bash /opt/sbx/images/build-rootfs.sh >/dev/null
install -m755 /tmp/qafas.new /opt/sbx/qafas
install -m755 /tmp/guest-agent.new /opt/sbx/guest-agent
systemctl restart qafas
sleep 4; systemctl is-active qafas
"
