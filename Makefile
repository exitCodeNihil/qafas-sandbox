.PHONY: help escape tools machine guest-agent qafas qafas-linux image image-amd64 rootfs cp web dev-local demo test agent-core sdk bench doctor install-launchd uninstall-launchd monitoring-up monitoring-down
.DEFAULT_GOAL := help
SHELL := /bin/bash

help:  ## Show this help message
	@echo "Qafas Sandbox — available targets:" && echo
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F: '{split($$2, a, "## "); print "  " $$1 "\t" a[2]}' | column -ts $$'\t'

tools:  ## Install Rust targets, Zig, and cargo-zigbuild
	rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
	brew install zig
	cargo install cargo-zigbuild

machine:  ## Configure and start podman machine
	@if [ "$$(podman machine inspect --format '{{.State}}' 2>/dev/null || echo 'none')" = "running" ]; then \
		echo "Machine already running"; \
	else \
		podman machine set --cpus 6 --memory 8192 2>/dev/null || true; \
		podman machine start; \
	fi

agent-core:  ## Build agent-core Rust crate
	cargo build -p agent-core

guest-agent:  ## Build guest-agent for both aarch64 and x86_64
	cargo zigbuild --release -p guest-agent --target aarch64-unknown-linux-musl
	cargo zigbuild --release -p guest-agent --target x86_64-unknown-linux-musl

qafas:  ## Build qafas for host macOS
	cargo build --release -p qafas

qafas-linux:  ## Build qafas for both Linux musl targets
	cargo zigbuild --release -p qafas --target aarch64-unknown-linux-musl
	cargo zigbuild --release -p qafas --target x86_64-unknown-linux-musl

image:  ## Build container image for arm64
	images/base/stage.sh
	podman build --platform linux/arm64 -t localhost/sbx-base:dev -f images/base/Dockerfile .

image-amd64:  ## Build container image for amd64 (emulated)
	images/base/stage.sh
	podman build --platform linux/amd64 -t localhost/sbx-base:dev -f images/base/Dockerfile .

rootfs:  ## Build rootfs.ext4 and vmlinux for Firecracker
	bash images/build-rootfs.sh

cp:  ## Build Go control plane binary
	cd controlplane && CGO_ENABLED=0 go build -o ../bin/controlplane ./cmd/controlplane

web:  ## Build React UI for production
	npm --prefix web run build

sdk:  ## Build TypeScript SDK
	cd sdk/ts && npm i && npm run build

BACKEND ?= native
bench:  ## Run benchmark suite (BACKEND=native|vm|remote|e2b, default native)
	node bench/run.mjs --backend $(BACKEND)

TIER ?= native
escape:  ## Run the adversarial escape battery against a running daemon (TIER=native|vm)
	node tests/escape.mjs http://127.0.0.1:7700 $(SBX_TOKEN) $(TIER) $$(pwd)/examples/hello

sweep:  ## Open every dashboard page for every session/sandbox in the control plane; fails on a page error
	SBX_ADMIN_TOKEN=$(SBX_ADMIN_TOKEN) node tests/dashboard-sweep.mjs

doctor:  ## Print host capabilities and tier support
	./target/release/qafas doctor

install-launchd:  ## Install qafas as a macOS launchd service
	@mkdir -p ~/Library/LaunchAgents
	@cp deploy/launchd/com.sbx.qafas.plist ~/Library/LaunchAgents/com.sbx.qafas.plist
	launchctl load ~/Library/LaunchAgents/com.sbx.qafas.plist
	@echo "Installed. Logs: log stream --predicate 'process == \"qafas\"' --level debug"

uninstall-launchd:  ## Uninstall qafas launchd service
	launchctl unload ~/Library/LaunchAgents/com.sbx.qafas.plist 2>/dev/null || true
	rm -f ~/Library/LaunchAgents/com.sbx.qafas.plist

SBX_TOKEN ?= dev
SBX_ADMIN_TOKEN ?= admin
SBX_HOST_TOKEN ?= host
SBX_PODMAN_SOCK ?= $(shell podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null)
# Exported only for the targets that run the daemons; `make test` must see a clean env.
dev-local: export SBX_TOKEN := $(SBX_TOKEN)
dev-local: export SBX_ADMIN_TOKEN := $(SBX_ADMIN_TOKEN)
dev-local: export SBX_HOST_TOKEN := $(SBX_HOST_TOKEN)
dev-local: export SBX_PODMAN_SOCK := $(SBX_PODMAN_SOCK)

dev-local: qafas cp web  ## Run controlplane + qafas (podman) with native tier in the foreground
	trap 'kill 0' EXIT; \
	SBX_TOKEN_SECRET=$(SBX_TOKEN) ./bin/controlplane & \
	SBX_TIERS=$${SBX_TIERS:-native,vm} SBX_CP_URL=http://localhost:7800 SBX_POLICY=policy/egress.json ./target/release/qafas serve

monitoring-up:  ## Start monitoring stack (Prometheus, Grafana, AlertManager, Jaeger)
	@if [ ! -f deploy/monitoring/.env ]; then \
		cp deploy/monitoring/.env.example deploy/monitoring/.env; \
		echo "Created deploy/monitoring/.env — edit and re-run"; \
		exit 1; \
	fi
	@sh -c '. ./deploy/monitoring/.env && printf "%s" "$$SBX_METRICS_TOKEN" > deploy/monitoring/token'
	docker compose -f deploy/monitoring/compose.yml up -d || podman-compose -f deploy/monitoring/compose.yml up -d
	@echo "Grafana: http://localhost:3000"
	@echo "Prometheus: http://localhost:9090"
	@echo "AlertManager: http://localhost:9093"
	@echo "Jaeger: http://localhost:16686 (OTLP push target: http://localhost:4318/v1/traces)"

monitoring-down:  ## Stop monitoring stack
	docker compose -f deploy/monitoring/compose.yml down || podman-compose -f deploy/monitoring/compose.yml down

demo:  ## Run pi demo against a sandbox
	cd examples/hello && \
	pi -e ../../pi-extension "list files, run node -v, open https://example.com and read the title"

test:  ## Run all tests (Rust + Go + TypeScript)
	cargo test --workspace
	cd controlplane && go test ./...
	npm --prefix web run typecheck
	cd pi-extension && npx tsc --noEmit
	if [ -d sdk/ts ]; then cd sdk/ts && npx tsc --noEmit; fi
