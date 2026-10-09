// settings.go: v4 observability settings (docs/protocol.md §4 v4 GET/PUT/test
// /api/settings/observability, docs/decisions.md D24). One row in the `settings` table
// (key="observability"), JSON-encoded — same shape used for PUT decode, the otlp.Pusher's
// per-batch destination resolution, and (masked) the GET response.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// ObservabilitySettings is the stored/internal shape. SecretKey is the raw secret; callers
// that build an HTTP response MUST mask it (docs/protocol.md: "the secret is never
// returned").
type ObservabilitySettings struct {
	Enabled     bool              `json:"enabled"`
	Provider    string            `json:"provider"` // "langfuse" | "otlp"
	Host        string            `json:"host,omitempty"`
	PublicKey   string            `json:"public_key,omitempty"`
	SecretKey   string            `json:"secret_key,omitempty"`
	OTLPURL     string            `json:"otlp_url,omitempty"`
	OTLPHeaders map[string]string `json:"otlp_headers,omitempty"`
	Capture     string            `json:"capture,omitempty"` // "all" | "alerts_only"
	// EnabledAt is set when export flips on. Only sessions active since then are
	// pushed, so turning export on never dumps the whole history at an external
	// endpoint (design: a "backfill" switch is the upgrade if anyone wants it).
	EnabledAt string `json:"enabled_at,omitempty"`
}

const observabilityKey = "observability"

// GetObservabilitySettings returns the stored row, or the default (disabled, otlp
// provider, capture all) when it has never been written.
func (s *Store) GetObservabilitySettings(ctx context.Context) (ObservabilitySettings, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, observabilityKey).Scan(&value)
	if err == sql.ErrNoRows {
		return ObservabilitySettings{Provider: "otlp", Capture: "all"}, nil
	}
	if err != nil {
		return ObservabilitySettings{}, err
	}
	var out ObservabilitySettings
	if err := json.Unmarshal([]byte(value), &out); err != nil {
		return ObservabilitySettings{}, err
	}
	return out, nil
}

// SetObservabilitySettings replaces the stored row.
func (s *Store) SetObservabilitySettings(ctx context.Context, settings ObservabilitySettings) error {
	b, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, observabilityKey, string(b))
	return err
}

// SeedObservabilitySettingsFromEnv writes SBX_OTLP_URL/SBX_OTLP_HEADERS as the initial
// otlp-provider settings, but only if the row does not exist yet (docs/protocol.md §4 v4:
// "SBX_OTLP_URL/SBX_OTLP_HEADERS seed the row on first boot only"). A no-op once the UI (or
// a prior boot) has written anything, and when otlpURL is empty.
func (s *Store) SeedObservabilitySettingsFromEnv(ctx context.Context, otlpURL string, otlpHeaders map[string]string) error {
	if otlpURL == "" {
		return nil
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM settings WHERE key=?`, observabilityKey).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return nil
	}
	return s.SetObservabilitySettings(ctx, ObservabilitySettings{
		Enabled: true, Provider: "otlp", OTLPURL: otlpURL, OTLPHeaders: otlpHeaders, Capture: "all",
		EnabledAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
}
