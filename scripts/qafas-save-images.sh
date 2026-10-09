#!/usr/bin/env bash
# Pulls every image a Qafas Sandbox release runs and saves them into one tarball, to carry
# into an air-gapped site (docs/airgap.md). Run it on a machine with internet access.
#
#   qafas-save-images.sh [--image-list images.txt] [--images qafas-images-<arch>.tar.gz]
#                        [--platform linux/amd64|linux/arm64]
#
#   --image-list  one image per line, as published with each release (images.txt)
#   --images      the tarball to write (default: qafas-images-<arch>.tar.gz)
#   --platform    the architecture the target hosts run (default: this machine's)
#
# Uses docker, or podman where there is no docker; CONTAINER_CLI=podman chooses. Then load
# it inside with qafas-load-images.sh.
set -euo pipefail

list=images.txt images="" platform=""
while [ $# -gt 0 ]; do
	case "$1" in
	--image-list) list="$2"; shift 2 ;;
	--images) images="$2"; shift 2 ;;
	--platform) platform="$2"; shift 2 ;;
	-h | --help) sed -n '2,13p' "$0"; exit 0 ;;
	*) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
	esac
done

cli="${CONTAINER_CLI:-$(command -v docker >/dev/null && echo docker || echo podman)}"
command -v "$cli" >/dev/null || { echo "neither docker nor podman is installed" >&2; exit 1; }
if [ -z "$platform" ]; then
	case "$(uname -m)" in
	x86_64 | amd64) platform=linux/amd64 ;;
	aarch64 | arm64) platform=linux/arm64 ;;
	*) echo "unknown architecture $(uname -m); pass --platform" >&2; exit 1 ;;
	esac
fi
images="${images:-qafas-images-${platform#linux/}.tar.gz}"

# Blank lines and # comments are allowed in the list. (No mapfile: macOS ships bash 3.2.)
refs=()
while read -r ref; do refs+=("$ref"); done < <(sed -e 's/#.*//' -e 's/[[:space:]]//g' "$list" | grep -v '^$')
[ "${#refs[@]}" -gt 0 ] || { echo "$list lists no images" >&2; exit 1; }

for ref in "${refs[@]}"; do
	echo "pulling $ref ($platform)"
	"$cli" pull --platform "$platform" "$ref" >/dev/null
done

echo "saving ${#refs[@]} images to $images"
case "$cli" in
*podman) "$cli" save -m "${refs[@]}" | gzip >"$images" ;; # -m: several images in one archive
*) "$cli" save "${refs[@]}" | gzip >"$images" ;;
esac
sha256sum "$images" 2>/dev/null || shasum -a 256 "$images"
