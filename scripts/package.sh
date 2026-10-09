#!/usr/bin/env bash
# Linux packages (deb + rpm, arm64 + amd64) and the generated files the container images
# COPY, from binaries that are already built:
#   target/{aarch64,x86_64}-unknown-linux-musl/release/qafas   make qafas-linux
#   dist/controlplane-linux-{arm64,amd64}                        go build (release.yml / ci.yml)
#   sdk/ts/dist                                                  npm ci && npm run build
# Usage: scripts/package.sh <version> [out-dir]     Needs nfpm: https://nfpm.goreleaser.com
set -euo pipefail
cd "$(dirname "$0")/.."
V=${1:?version}
OUT=${2:-out}
IMG="ghcr.io/exitcodenihil/qafas-sandbox/sbx-base:$V"
mkdir -p "$OUT" dist/cli dist/empty

# Generated inputs (dist/ is also the build context deploy/docker/Dockerfile.* read).
sed "s#localhost/sbx-base:dev#$IMG#g" images/templates.json > dist/templates.json
printf '[Service]\nEnvironment=SBX_TEMPLATE_IMAGE=%s\n' "$IMG" > dist/image.conf
rm -rf dist/cli/package
(cd sdk/ts && npm pack --pack-destination ../../dist >/dev/null 2>&1)
tar -xzf "dist/qafas-sandbox-$V.tgz" -C dist/cli

# nfpm does not expand ${VAR} inside contents.src, so the specs are rendered here.
pkg() { # <spec> <arch> <qafas> <cp>
	sed "s#\${VERSION}#$V#g; s#\${STAGE}#dist#g; s#\${ARCH}#$2#g; s#\${QAFAS}#$3#g; s#\${CP}#$4#g" \
		"packaging/nfpm/$1.yaml" > "dist/nfpm-$1-$2.yaml"
	for p in deb rpm; do nfpm package -f "dist/nfpm-$1-$2.yaml" -p "$p" -t "$OUT" >/dev/null; done
}
for pair in arm64:aarch64-unknown-linux-musl amd64:x86_64-unknown-linux-musl; do
	arch=${pair%%:*}
	pkg qafas "$arch" "target/${pair#*:}/release/qafas" -
	pkg qafas-controlplane "$arch" - "dist/controlplane-linux-$arch"
done
pkg qafas-cli all - -
ls -1 "$OUT"/*.deb "$OUT"/*.rpm
