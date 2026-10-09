# Multi-arch base image: guest-agent is the container entrypoint (PID 1 in Firecracker,
# ordinary entrypoint here); qafas is copied in too so the same image can run the
# podman-mode egress proxy container (`qafas proxy`).
#
# Binary staging: Rust's target triples (aarch64-unknown-linux-musl,
# x86_64-unknown-linux-musl) don't match Docker/Podman's $TARGETARCH (arm64, amd64), so
# `images/base/stage.sh` copies WP1's release binaries into
# images/base/bin/<amd64|arm64>/{guest-agent,qafas} before this build runs. Build with:
#   images/base/stage.sh && podman build --platform linux/arm64 -t localhost/sbx-base:dev -f images/base/Dockerfile .
FROM debian:bookworm-slim
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
	npm_config_ignore_scripts=true \
	PLAYWRIGHT_BROWSERS_PATH=/opt/pw

# git curl ripgrep fd-find iproute2 ca-certificates build-essential python3, plus the chrome-headless-shell runtime libs it needs even without full chromium.
RUN apt-get update && apt-get install -y --no-install-recommends \
		git curl ripgrep fd-find iproute2 ca-certificates build-essential python3 \
		libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
		libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 \
		libasound2 libatspi2.0-0 libx11-6 libxcb1 libxext6 fonts-liberation \
		bpftrace \
	&& ln -s /usr/bin/fdfind /usr/local/bin/fd \
	&& rm -rf /var/lib/apt/lists/*

# uv (PLAN §9: "python3 + uv").
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# Node 22 (NodeSource).
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
	&& apt-get install -y --no-install-recommends nodejs \
	&& rm -rf /var/lib/apt/lists/*

# chrome-headless-shell pinned to 1.63 to match playwright-core in pi-extension/package.json.
# design: `find` + glob because the exact install subdir name is a playwright
# implementation detail; if this breaks on a playwright bump, `npx playwright@1.63
# install --dry-run --only-shell chromium` prints the real path to hardcode instead.
RUN npx --yes playwright@1.63 install --only-shell chromium \
	&& shell_bin="$(find /opt/pw -maxdepth 3 -type f \( -name 'chrome-headless-shell' -o -name 'headless_shell' \) | head -n1)" \
	&& test -n "$shell_bin" \
	&& ln -s "$shell_bin" /usr/local/bin/chrome-headless-shell

RUN useradd -u 1000 -m -s /bin/bash agent \
	&& mkdir -p /overlay `# mount point for the microVM's tmpfs overlay (guest-agent init)` \
	&& chmod 711 /root    # a /root/<dir> workspace is mounted under here; uid 1000 must get through

COPY images/base/bin/${TARGETARCH}/guest-agent /usr/local/bin/guest-agent
COPY images/base/bin/${TARGETARCH}/qafas /usr/local/bin/qafas
RUN chmod +x /usr/local/bin/guest-agent /usr/local/bin/qafas

# USER stays root at entry: guest-agent itself drops to uid 1000 before running the
# agent's own exec/fs/browser handlers (crates/guest-agent harden::apply(), PLAN §3).
# Chromium is launched as uid 1000 by guest-agent, never with --single-process (D12).
USER root
ENTRYPOINT ["/usr/local/bin/guest-agent"]
