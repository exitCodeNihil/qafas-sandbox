// Package otlp pushes each active session's trace to an external OTLP/HTTP collector,
// per docs/protocol.md §1.2/§4 v4. No OTel SDK: this is a batch POST of the same
// ExportTraceServiceRequest JSON that GET /api/sessions/{id}/trace returns (docs/decisions.md
// D20). The destination is admin-editable (docs/protocol.md §4 v4 /api/settings/observability):
// "langfuse" points this at Langfuse's OTLP receiver with basic auth, "otlp" is a plain
// collector URL + headers (docs/decisions.md D24).
package otlp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/trace"
)

// Health is the pusher's own delivery counters, surfaced under GET
// /api/settings/observability's `health` field.
type Health struct {
	Delivered int64  `json:"delivered"`
	Dropped   int64  `json:"dropped"`
	LastOkTS  string `json:"last_ok_ts,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// Pusher batches and pushes only new/completed spans per session every interval, tracked
// by a per-session "already sent" span-id set kept in memory (design: lost on restart — a
// restart re-sends every completed span once; the collector de-dupes on span id).
//
// settingsFn is read fresh every batch (docs/protocol.md §4 v4: "applied live: the pusher
// re-reads it every batch"), so flipping `enabled` or switching provider from the UI takes
// effect on the next tick with no restart. The Pusher is always constructed and Run; an
// `enabled:false` row just makes pushOnce a no-op.
type Pusher struct {
	settingsFn func() store.ObservabilitySettings
	store      *store.Store
	client     *http.Client
	log        *slog.Logger
	sentSpans  map[string]map[string]bool // pi_session -> span_id -> sent

	healthMu sync.Mutex
	health   Health
}

func NewPusher(settingsFn func() store.ObservabilitySettings, s *store.Store, log *slog.Logger) *Pusher {
	if log == nil {
		log = slog.Default()
	}
	return &Pusher{
		settingsFn: settingsFn, store: s, log: log,
		client:    &http.Client{Timeout: 10 * time.Second},
		sentSpans: map[string]map[string]bool{},
	}
}

// Health returns a snapshot of the delivery counters.
func (p *Pusher) Health() Health {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	return p.health
}

func (p *Pusher) recordDelivered(n int) {
	p.healthMu.Lock()
	p.health.Delivered += int64(n)
	p.health.LastOkTS = time.Now().UTC().Format(time.RFC3339)
	p.healthMu.Unlock()
}

func (p *Pusher) recordDropped(n int, errMsg string) {
	p.healthMu.Lock()
	p.health.Dropped += int64(n)
	p.health.LastError = errMsg
	p.healthMu.Unlock()
}

func (p *Pusher) recordConfigError(errMsg string) {
	p.healthMu.Lock()
	p.health.LastError = errMsg
	p.healthMu.Unlock()
}

// Run pushes every interval until ctx is cancelled.
func (p *Pusher) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.pushOnce(ctx); err != nil {
				p.log.Warn("otlp push", "err", err)
			}
		}
	}
}

// destination resolves the collector URL and headers for one batch from the stored
// settings (docs/protocol.md §4 v4): "langfuse" -> Langfuse's OTLP receiver with HTTP
// basic auth over public_key:secret_key, "otlp" -> otlp_url/otlp_headers verbatim.
func destination(s store.ObservabilitySettings) (url string, headers map[string]string, err error) {
	switch s.Provider {
	case "langfuse":
		if s.Host == "" || s.PublicKey == "" || s.SecretKey == "" {
			return "", nil, fmt.Errorf("langfuse: host, public_key and secret_key are required")
		}
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.PublicKey+":"+s.SecretKey))
		return strings.TrimSuffix(s.Host, "/") + "/api/public/otel/v1/traces", map[string]string{"Authorization": auth}, nil
	case "otlp", "":
		if s.OTLPURL == "" {
			return "", nil, fmt.Errorf("otlp: otlp_url is required")
		}
		return s.OTLPURL, s.OTLPHeaders, nil
	default:
		return "", nil, fmt.Errorf("unknown observability provider %q", s.Provider)
	}
}

// hasAlert reports whether a session summary raised any security.alert, for
// capture:"alerts_only" (docs/protocol.md §4 v4).
func hasAlert(a store.AlertCounts) bool { return a.Critical+a.High+a.Medium+a.Low > 0 }

func (p *Pusher) pushOnce(ctx context.Context) error {
	settings := p.settingsFn()
	if !settings.Enabled {
		return nil
	}
	url, headers, err := destination(settings)
	if err != nil {
		// A misconfigured destination surfaces via health.last_error on the settings page,
		// not a log-spam retry loop every 5s.
		p.recordConfigError(err.Error())
		return nil
	}

	sessions, err := p.store.ListSessions(ctx, 200, "", "")
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if settings.Capture == "alerts_only" && !hasAlert(sess.Alerts) {
			continue
		}
		// Sessions that ended before export was enabled are history, not telemetry.
		if settings.EnabledAt != "" && sess.LastTS < settings.EnabledAt {
			continue
		}
		evs, err := p.store.ListAllSessionEvents(ctx, sess.PiSession)
		if err != nil {
			return err
		}
		spans := trace.BuildSpans(sess.PiSession, evs)
		sent := p.sentSpans[sess.PiSession]
		if sent == nil {
			sent = map[string]bool{}
			p.sentSpans[sess.PiSession] = sent
		}
		var fresh []trace.Span
		for _, sp := range spans {
			if !sp.Completed || sent[sp.SpanID] {
				continue
			}
			fresh = append(fresh, sp)
		}
		if len(fresh) == 0 {
			continue
		}
		req := trace.Build(sess.PiSession, nil) // envelope only; fill spans below
		req.ResourceSpans[0].ScopeSpans[0].Spans = fresh
		if err := p.send(ctx, url, headers, req); err != nil {
			// design: one session's delivery failure doesn't block the rest of the batch; it
			// shows up in health.dropped/last_error and is retried next tick (nothing is
			// marked sent below).
			p.log.Warn("otlp push session", "pi_session", sess.PiSession, "err", err)
			p.recordDropped(len(fresh), err.Error())
			continue
		}
		for _, sp := range fresh {
			sent[sp.SpanID] = true
		}
		p.recordDelivered(len(fresh))
	}
	return nil
}

func (p *Pusher) send(ctx context.Context, url string, headers map[string]string, req *trace.ExportTraceServiceRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("otlp collector %s: %d", url, resp.StatusCode)
	}
	return nil
}

// Test checks reachability/credentials for a settings config, for POST
// /api/settings/observability/test (docs/protocol.md §4 v4). Never touches the Pusher's
// own health/sent-span state. 8s timeout; never logs or returns the secret.
func Test(ctx context.Context, s store.ObservabilitySettings) (ok bool, detail string) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 8 * time.Second}

	if s.Provider == "langfuse" {
		if s.Host == "" || s.PublicKey == "" || s.SecretKey == "" {
			return false, "host, public_key and secret_key are required"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(s.Host, "/")+"/api/public/health", nil)
		if err != nil {
			return false, err.Error()
		}
		resp, err := client.Do(req)
		if err != nil {
			return false, "host unreachable: " + err.Error()
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			return false, fmt.Sprintf("host unreachable: health check returned %d", resp.StatusCode)
		}
	}

	url, headers, err := destination(s)
	if err != nil {
		return false, err.Error()
	}
	body, _ := json.Marshal(map[string]any{"resourceSpans": []any{}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, "host unreachable: " + err.Error()
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, "credentials rejected"
	case resp.StatusCode >= 300:
		return false, fmt.Sprintf("unexpected status %d", resp.StatusCode)
	default:
		return true, "ok"
	}
}
