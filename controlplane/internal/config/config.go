// Package config reads flags with environment-variable fallback (docs/deployment.md).
package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

type Config struct {
	Listen      string
	DB          string
	AdminToken  string
	HostToken   string
	TokenSecret string

	RetentionDays int               // v2: SBX_RETENTION_DAYS, 0 disables the sweeper
	OTLPURL       string            // v2: SBX_OTLP_URL, push disabled when empty
	OTLPHeaders   map[string]string // v2: SBX_OTLP_HEADERS, "K1=V1,K2=V2"

	CAFile      string // v2: SBX_CA_FILE, CA bundle qafas certificates are verified against
	TLSInsecure bool   // v2: SBX_TLS_INSECURE=1, skip verification entirely (dev only)

	// SBX_TLS_CERT / SBX_TLS_KEY: serve HTTPS with this PEM pair; both or neither.
	TLSCert string
	TLSKey  string

	// v5 (docs/protocol.md §3a "v5 sizes and limits").
	Sizes         map[string]events.SandboxLimits // SBX_SIZES: JSON table, replaces events.DefaultSizes() wholesale
	OvercommitCPU float64                         // SBX_OVERCOMMIT_CPU, default 1.0
	OvercommitMem float64                         // SBX_OVERCOMMIT_MEM, default 1.0
}

// env returns the environment value for key, or def if unset/empty.
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Load parses flags (with env fallback for defaults) from args (excluding argv[0]).
func Load(args []string) (*Config, error) {
	fs := flag.NewFlagSet("controlplane", flag.ContinueOnError)
	cfg := &Config{}
	fs.StringVar(&cfg.Listen, "listen", env("SBX_LISTEN", ":7800"), "listen address")
	fs.StringVar(&cfg.DB, "db", env("SBX_DB", "sandbox.db"), "sqlite database path")
	fs.StringVar(&cfg.AdminToken, "admin-token", env("SBX_ADMIN_TOKEN", ""), "admin bearer token")
	fs.StringVar(&cfg.HostToken, "host-token", env("SBX_HOST_TOKEN", ""), "host bearer token")
	fs.StringVar(&cfg.TokenSecret, "token-secret", env("SBX_TOKEN_SECRET", ""), "HMAC secret for scoped sandbox tokens")
	retentionStr := fs.String("retention-days", env("SBX_RETENTION_DAYS", "30"), "days of events to retain (0 disables the sweeper)")
	fs.StringVar(&cfg.OTLPURL, "otlp-url", env("SBX_OTLP_URL", ""), "OTLP/HTTP collector URL to push session traces to (empty disables push)")
	headersStr := fs.String("otlp-headers", env("SBX_OTLP_HEADERS", ""), `OTLP push headers, "K1=V1,K2=V2"`)
	fs.StringVar(&cfg.CAFile, "ca-file", env("SBX_CA_FILE", ""), "CA bundle to verify qafas TLS certificates against (empty: pin the fingerprint each host registered with)")
	fs.BoolVar(&cfg.TLSInsecure, "tls-insecure", env("SBX_TLS_INSECURE", "") == "1", "do not verify qafas TLS certificates (dev only)")
	fs.StringVar(&cfg.TLSCert, "tls-cert", env("SBX_TLS_CERT", ""), "PEM certificate (chain) to serve HTTPS with; needs -tls-key")
	fs.StringVar(&cfg.TLSKey, "tls-key", env("SBX_TLS_KEY", ""), "PEM private key for -tls-cert")
	sizesStr := fs.String("sizes", env("SBX_SIZES", ""), "JSON size table {name:{cpus,mem_mib,disk_mib,pids}}, replaces the compiled default wholesale")
	overcommitCPUStr := fs.String("overcommit-cpu", env("SBX_OVERCOMMIT_CPU", "1.0"), "cpu overcommit factor for placement")
	overcommitMemStr := fs.String("overcommit-mem", env("SBX_OVERCOMMIT_MEM", "1.0"), "memory overcommit factor for placement")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	days, err := strconv.Atoi(*retentionStr)
	if err != nil {
		return nil, err
	}
	cfg.RetentionDays = days
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return nil, fmt.Errorf("SBX_TLS_CERT and SBX_TLS_KEY go together: set both or neither")
	}
	cfg.OTLPHeaders = parseHeaders(*headersStr)

	cfg.Sizes = events.DefaultSizes()
	if *sizesStr != "" {
		var custom map[string]events.SandboxLimits
		if err := json.Unmarshal([]byte(*sizesStr), &custom); err != nil {
			return nil, fmt.Errorf("SBX_SIZES: %w", err)
		}
		cfg.Sizes = custom
	}
	if cfg.OvercommitCPU, err = strconv.ParseFloat(*overcommitCPUStr, 64); err != nil {
		return nil, fmt.Errorf("SBX_OVERCOMMIT_CPU: %w", err)
	}
	if cfg.OvercommitMem, err = strconv.ParseFloat(*overcommitMemStr, 64); err != nil {
		return nil, fmt.Errorf("SBX_OVERCOMMIT_MEM: %w", err)
	}
	return cfg, nil
}

func parseHeaders(s string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if k, v, ok := strings.Cut(pair, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}
