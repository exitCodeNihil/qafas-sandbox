#!/usr/bin/env bash
# Loads the tarball qafas-save-images.sh wrote, and pushes its images into a private
# registry when one is named (docs/airgap.md). Run it inside the air-gapped site.
#
#   qafas-load-images.sh --images qafas-images-<arch>.tar.gz [--image-list images.txt]
#                        [--registry host[:port]] [--tls-verify=false]
#
#   --images      the tarball from qafas-save-images.sh
#   --image-list  the images.txt it was saved from (default: images.txt)
#   --registry    push each image there, under its path without the source registry:
#                 ghcr.io/exitcodenihil/qafas-sandbox/sbx-base:0.8.0
#                   -> <registry>/exitcodenihil/qafas-sandbox/sbx-base:0.8.0
#                 Without it the images are only loaded into this host's podman or docker.
#   --tls-verify=false  push to a registry without a trusted certificate (podman only;
#                 for docker, list it under insecure-registries in /etc/docker/daemon.json)
#
# Uses podman, or docker where there is no podman: the runtime the qafas package uses (it
# turns on podman.socket wherever podman is installed). CONTAINER_CLI=docker chooses, for
# the container install on a host that has both. Log in to the registry first if it needs
# credentials (podman login / docker login).
# ponytail: one architecture per run, as saved; a mixed-architecture fleet pushes each
# tarball under its own registry path, or uses `skopeo copy --all` from a connected machine.
set -euo pipefail

images="" list=images.txt registry="" tls=()
while [ $# -gt 0 ]; do
	case "$1" in
	--images) images="$2"; shift 2 ;;
	--image-list) list="$2"; shift 2 ;;
	--registry) registry="${2%/}"; shift 2 ;;
	--tls-verify=false) tls=(--tls-verify=false); shift ;;
	-h | --help) sed -n '2,20p' "$0"; exit 0 ;;
	*) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
	esac
done
[ -n "$images" ] || { echo "--images <tarball> is required (see --help)" >&2; exit 2; }

cli="${CONTAINER_CLI:-$(command -v podman >/dev/null && echo podman || echo docker)}"
command -v "$cli" >/dev/null || { echo "neither docker nor podman is installed" >&2; exit 1; }
[ "${#tls[@]}" -eq 0 ] || [[ "$cli" == *podman ]] || {
	echo "--tls-verify=false is podman's; docker reads insecure-registries from daemon.json" >&2
	exit 2
}

echo "loading $images"
"$cli" load -i "$images"
[ -n "$registry" ] || exit 0

refs=()
while read -r ref; do refs+=("$ref"); done < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$list" | grep -v '^$')
[ "${#refs[@]}" -gt 0 ] || { echo "$list lists no images" >&2; exit 1; }

for ref in "${refs[@]}"; do
	# The first path segment is a registry when there is a "/" after it and it has a dot
	# or a port, or is localhost.
	path="$ref"
	if [[ "$ref" == */* ]]; then
		case "${ref%%/*}" in *.* | *:* | localhost) path="${ref#*/}" ;; esac
	fi
	target="$registry/$path"
	echo "pushing $target"
	"$cli" tag "$ref" "$target"
	"$cli" push "${tls[@]+"${tls[@]}"}" "$target" >/dev/null
done

base=$(printf '%s\n' "${refs[@]}" | grep '/sbx-base:' | head -1 || true)
if [ -n "$base" ]; then
	cat <<EOF

Done. Point each worker at the guest image in $registry, for example:
  printf '[Service]\nEnvironment=SBX_TEMPLATE_IMAGE=$registry/${base#*/}\n' |
    sudo tee /etc/systemd/system/qafas.service.d/registry.conf && sudo systemctl daemon-reload
(podman workers can mirror the ghcr.io name instead: docs/airgap.md, Method B.)
EOF
fi
