#!/usr/bin/env bash
# Builds the Firecracker rootfs + kernel for the remote (Linux/KVM) backend:
# `podman export` the already-built base image into an ext4 image, and fetch the
# matching Firecracker CI kernel. The release runs it once per arch to make the
# qafas-firecracker-<v>-<arch>.tar.zst bundle; a worker never needs to.
#
# Requirements (this is genuinely Linux-only, unlike the rest of the POC's tooling):
#   - Run on the Linux/KVM remote box, not the Mac (podman export + mkfs.ext4 -d
#     preserving real uid/gid, incl. uid 1000, needs root; the Mac's podman machine is
#     itself a Linux VM one layer removed and complicates that further — do it on the box).
#   - `localhost/sbx-base:dev` (or $SBX_IMAGE) already in podman's store, for the host's
#     arch or for $SBX_ARCH (x86_64 | aarch64): export runs nothing, so a foreign-arch
#     image needs no emulation.
#   - root or sudo (for `tar --numeric-owner` extraction and `mkfs.ext4 -d`, both of
#     which must preserve the uid 1000 files the image assigns to the `agent` user).
#   - e2fsprogs with `mkfs.ext4 -d` (populate-from-directory; standard since e2fsprogs
#     1.44, 2018 — anything remotely current has it).
#
# Output: images/out/rootfs.ext4, images/out/vmlinux (for $SBX_ARCH, default the host's).
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
	echo "error: build-rootfs.sh must run on Linux (podman export + mkfs.ext4 -d need real uid/gid preservation); this is not that box." >&2
	exit 1
fi
if [[ "$(id -u)" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
	echo "error: need root or sudo (tar --numeric-owner extraction and mkfs.ext4 -d must run privileged to preserve uid 1000)." >&2
	exit 1
fi
SUDO=""
[[ "$(id -u)" -ne 0 ]] && SUDO="sudo"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${REPO_ROOT}/images/out"
IMAGE="${SBX_IMAGE:-localhost/sbx-base:dev}"
ROOTFS_SIZE_MB="${SBX_ROOTFS_SIZE_MB:-2048}"

# Firecracker CI test kernels (public, unsigned — good enough for a POC; verified
# present at time of writing via the bucket's ListObjectsV2). Firecracker's own
# kernel-policy.md marks the 5.10/6.1 guest lines as lapsing in favor of 6.18, but no
# 6.18 CI artifact exists in the bucket yet, so 6.1.155 (the newest available) is what's
# pinned. Re-check https://s3.amazonaws.com/spec.ccfc.min/?list-type=2&prefix=firecracker-ci/
# for a v1.16+/6.18 kernel when this next needs updating.
FC_CI_VERSION="v1.15"
FC_KERNEL_VERSION="6.1.155"

case "${SBX_ARCH:-$(uname -m)}" in
x86_64) ARCH=x86_64 ;;
aarch64 | arm64) ARCH=aarch64 ;;
*)
	echo "error: unsupported arch ${SBX_ARCH:-$(uname -m)} (Firecracker CI kernels only exist for x86_64/aarch64)" >&2
	exit 1
	;;
esac
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/${FC_CI_VERSION}/${ARCH}/vmlinux-${FC_KERNEL_VERSION}"

mkdir -p "$OUT_DIR"

echo "== kernel: ${KERNEL_URL}"
[[ -s "${OUT_DIR}/vmlinux" ]] || curl -fL --retry 3 -o "${OUT_DIR}/vmlinux" "$KERNEL_URL"

echo "== exporting ${IMAGE} rootfs"
CONTAINER_ID="$(podman create --arch "$([[ $ARCH == x86_64 ]] && echo amd64 || echo arm64)" "$IMAGE" /bin/true)"
WORK_DIR="$(mktemp -d)"
# The extracted tree is root-owned, so only $SUDO can remove it.
trap 'podman rm -f "$CONTAINER_ID" >/dev/null 2>&1 || true; $SUDO rm -rf "$WORK_DIR"' EXIT

podman export "$CONTAINER_ID" -o "${WORK_DIR}/rootfs.tar"

EXTRACT_DIR="${WORK_DIR}/root"
mkdir -p "$EXTRACT_DIR"
# --numeric-owner: preserve the image's uid/gid (1000 for `agent`) rather than remapping
# to whoever runs this script.
$SUDO tar --numeric-owner -xpf "${WORK_DIR}/rootfs.tar" -C "$EXTRACT_DIR"

# guest-agent boots this as init=; it needs somewhere to mount proc/sys/dev/tmp/run
# (crates/guest-agent init::boot(), PLAN §3) even though the container image never
# needed them as real directories.
for d in proc sys dev dev/pts tmp run; do
	$SUDO mkdir -p "${EXTRACT_DIR:?}/${d}"
done

echo "== building ext4 image (${ROOTFS_SIZE_MB}MiB)"
rm -f "${OUT_DIR}/rootfs.ext4"
$SUDO mkfs.ext4 -F -q -d "$EXTRACT_DIR" "${OUT_DIR}/rootfs.ext4" "${ROOTFS_SIZE_MB}M"
$SUDO chown "$(id -u):$(id -g)" "${OUT_DIR}/rootfs.ext4"

echo "== done: ${OUT_DIR}/rootfs.ext4 ${OUT_DIR}/vmlinux"
