#!/usr/bin/env bash
# Stages WP1's release binaries into images/base/bin/<docker-arch>/ so the Dockerfile
# can `COPY` them by $TARGETARCH without needing to know Rust target-triple names
# (Rust's aarch64-unknown-linux-musl / x86_64-unknown-linux-musl don't match Docker's
# arm64 / amd64). Run this before `podman build`; the Makefile's `image` target does.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # repo root

staged_any=0
for pair in arm64:aarch64-unknown-linux-musl amd64:x86_64-unknown-linux-musl; do
	docker_arch="${pair%%:*}"; triple="${pair#*:}"
	src="target/${triple}/release"
	dst="images/base/bin/${docker_arch}"
	if [[ -f "$src/guest-agent" && -f "$src/qafas" ]]; then
		mkdir -p "$dst"
		cp "$src/guest-agent" "$src/qafas" "$dst/"
		echo "staged ${docker_arch} <- ${src}"
		staged_any=1
	else
		echo "skip ${docker_arch}: ${src}/{guest-agent,qafas} not built yet" >&2
	fi
done

if [[ "$staged_any" -eq 0 ]]; then
	echo "error: no arch staged; run 'make guest-agent qafas-linux' first" >&2
	exit 1
fi
