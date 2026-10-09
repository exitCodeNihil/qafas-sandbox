package registry

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func register(t *testing.T, s *store.Store, id string, tiers []string, warm uint32) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertHost(ctx, events.HostRegister{HostID: id, URL: "http://" + id, Backend: "podman", Capacity: 4, Tiers: tiers}); err != nil {
		t.Fatalf("UpsertHost(%s): %v", id, err)
	}
	if warm > 0 {
		if err := s.Heartbeat(ctx, id, events.Heartbeat{Pool: events.PoolStats{"base|/x": {Warm: warm, Target: warm}}}); err != nil {
			t.Fatalf("Heartbeat(%s): %v", id, err)
		}
	}
}

func TestPickHostForRequestExplicitTier(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "mac", []string{"native", "vm"}, 1)
	register(t, s, "linuxbox", []string{"remote"}, 3)

	h, tier, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "native"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	if err != nil || h.ID != "mac" || tier != "native" {
		t.Fatalf("isolation=native: err=%v host=%+v tier=%q", err, h, tier)
	}

	h, tier, err = PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "remote"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	if err != nil || h.ID != "linuxbox" || tier != "remote" {
		t.Fatalf("isolation=remote: err=%v host=%+v tier=%q", err, h, tier)
	}

	h, tier, err = PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "vm"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	if err != nil || h.ID != "mac" || tier != "vm" {
		t.Fatalf("isolation=vm: err=%v host=%+v tier=%q", err, h, tier)
	}

	// Alias accepted and normalised.
	h, tier, err = PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "firecracker"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	if err != nil || h.ID != "linuxbox" || tier != "remote" {
		t.Fatalf("isolation=firecracker alias: err=%v host=%+v tier=%q", err, h, tier)
	}
}

func TestPickHostForRequestUnavailableTier(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "mac", []string{"native"}, 1)

	_, _, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "remote"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	var pe *PlacementError
	if !errors.As(err, &pe) || pe.Status != http.StatusConflict || pe.Msg != "no host serves the remote runtime" {
		t.Fatalf("want a 409 PlacementError, got %v", err)
	}
}

func TestPickHostForRequestAutoTrusted(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "mac", []string{"native", "vm"}, 1)
	register(t, s, "linuxbox", []string{"vm", "remote"}, 5)

	// auto/trusted is Firecracker-first (D25): remote wins even though it's not the
	// bigger pool and native/vm are also servable.
	h, tier, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "auto", Trust: "trusted"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	if err != nil || h.ID != "linuxbox" || tier != "remote" {
		t.Fatalf("auto/trusted should prefer the remote host: err=%v host=%+v tier=%q", err, h, tier)
	}
}

// A host that stopped heartbeating must not win placement: auto prefers remote, so a
// dead remote host would otherwise swallow every request a live vm host could serve.
func TestPickHostForRequestSkipsStaleHosts(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "mac", []string{"native", "vm"}, 1)
	register(t, s, "deadbox", []string{"vm", "remote"}, 5)
	db, err := sql.Open("sqlite", s.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE hosts SET last_seen='2020-01-01T00:00:00.000Z' WHERE id='deadbox'`); err != nil {
		t.Fatal(err)
	}
	h, tier, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "auto", Trust: "trusted"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	if err != nil || h.ID != "mac" || tier != "vm" {
		t.Fatalf("a stale host must be skipped: err=%v host=%+v tier=%q", err, h, tier)
	}
}

func TestPickHostForRequestAutoUntrusted(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "mac", []string{"native", "vm"}, 1)
	register(t, s, "linuxbox", []string{"vm", "remote"}, 5)

	h, tier, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "auto", Trust: "untrusted"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	if err != nil || h.ID != "linuxbox" || tier != "remote" {
		t.Fatalf("auto/untrusted should prefer the remote host: err=%v host=%+v tier=%q", err, h, tier)
	}
}

func TestPickHostForRequestAutoUntrustedNativeOnly409(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "mac", []string{"native"}, 1)

	_, _, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Trust: "untrusted"}, nil, "tok", events.SandboxLimits{}, 1.0, 1.0)
	var pe *PlacementError
	if !errors.As(err, &pe) || pe.Status != http.StatusConflict {
		t.Fatalf("untrusted auto with only a native host: want 409 PlacementError, got %v", err)
	}
}

func TestPickHostForRequestAllowedTiersRestrictsAuto(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "linuxbox", []string{"remote"}, 5)
	register(t, s, "mac", []string{"native"}, 1)

	// allowed_tiers=[native] rules out remote even though it's first in the auto order.
	h, tier, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{}, []string{"native"}, "tok", events.SandboxLimits{}, 1.0, 1.0)
	if err != nil || h.ID != "mac" || tier != "native" {
		t.Fatalf("allowed_tiers should restrict auto: err=%v host=%+v tier=%q", err, h, tier)
	}
}

func TestPickHostForRequestExplicitTierOutsideAllowed403(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "linuxbox", []string{"remote"}, 5)

	_, _, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "remote"}, []string{"vm"}, "tok", events.SandboxLimits{}, 1.0, 1.0)
	var pe *PlacementError
	if !errors.As(err, &pe) || pe.Status != http.StatusForbidden {
		t.Fatalf("explicit tier outside allowed_tiers: want 403 PlacementError, got %v", err)
	}
}

// ---- v5: placement fit filter (docs/protocol.md §3a "v5 sizes and limits", §4)

func registerCapped(t *testing.T, s *store.Store, id string, tiers []string, cpus uint32, memMiB uint64) {
	t.Helper()
	if err := s.UpsertHost(context.Background(), events.HostRegister{
		HostID: id, URL: "http://" + id, Backend: "podman", Capacity: 4, Tiers: tiers,
		Caps: events.HostCaps{CPUs: cpus, MemMiB: memMiB},
	}); err != nil {
		t.Fatalf("UpsertHost(%s): %v", id, err)
	}
}

// commit inserts a live sandbox row with Limits set, so it counts toward the host's
// CommittedByHost sum.
func commit(t *testing.T, s *store.Store, hostID, sandboxID string, cpus float64, memMiB uint64) {
	t.Helper()
	err := s.CreateSandbox(context.Background(), events.SandboxInfo{
		ID: sandboxID, State: "ready", Isolation: "vm", CreatedAt: "2026-01-01T00:00:00Z",
		Limits: &events.SandboxLimits{Cpus: cpus, MemMiB: memMiB},
	}, hostID)
	if err != nil {
		t.Fatalf("commit sandbox on %s: %v", hostID, err)
	}
}

func TestPickHostForRequestFitsWithinFreeCapacity(t *testing.T) {
	s := newTestStore(t)
	registerCapped(t, s, "mac-local", []string{"vm"}, 4, 4096)
	commit(t, s, "mac-local", "sbx1", 2, 2560) // free: 2 cpus / 1536 MiB

	h, _, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "vm"}, nil, "tok", events.SandboxLimits{Cpus: 1, MemMiB: 1024}, 1.0, 1.0)
	if err != nil || h.ID != "mac-local" {
		t.Fatalf("request within free capacity: err=%v host=%+v", err, h)
	}
}

func TestPickHostForRequestOverCapacityIs503WithBestHost(t *testing.T) {
	s := newTestStore(t)
	registerCapped(t, s, "mac-local", []string{"vm"}, 4, 4096)
	commit(t, s, "mac-local", "sbx1", 2, 2560) // free: 2 cpus / 1536 MiB

	_, _, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "vm"}, nil, "tok", events.SandboxLimits{Cpus: 4, MemMiB: 4096}, 1.0, 1.0)
	var pe *PlacementError
	if !errors.As(err, &pe) || pe.Status != http.StatusServiceUnavailable {
		t.Fatalf("want a 503 PlacementError, got %v", err)
	}
	want := "no host has 4 cpus / 4096 MiB free (best: mac-local 2 cpus / 1536 MiB)"
	if pe.Msg != want {
		t.Fatalf("503 message: got %q, want %q", pe.Msg, want)
	}
}

func TestPickHostForRequestOvercommitWidensCeiling(t *testing.T) {
	s := newTestStore(t)
	registerCapped(t, s, "mac-local", []string{"vm"}, 4, 4096)
	commit(t, s, "mac-local", "sbx1", 2, 2560) // free at 1.0x: 2 cpus / 1536 MiB

	// Doesn't fit at 1.0x overcommit; does at 2.0x (caps*2 - committed = 6 cpus / 5632 MiB free).
	h, _, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "vm"}, nil, "tok", events.SandboxLimits{Cpus: 3, MemMiB: 2000}, 2.0, 2.0)
	if err != nil || h.ID != "mac-local" {
		t.Fatalf("overcommit should widen the ceiling: err=%v host=%+v", err, h)
	}
}

func TestPickHostForRequestZeroCapsIsUnlimited(t *testing.T) {
	s := newTestStore(t)
	register(t, s, "legacy", []string{"vm"}, 1) // pre-v4c: never registered caps at all

	h, _, err := PickHostForRequest(context.Background(), s, events.CreateSandboxReq{Isolation: "vm"}, nil, "tok", events.SandboxLimits{Cpus: 999, MemMiB: 999999}, 1.0, 1.0)
	if err != nil || h.ID != "legacy" {
		t.Fatalf("host with zero caps must be treated as unlimited: err=%v host=%+v", err, h)
	}
}

// A pinned host is reachable only with the certificate it registered with. The
// fingerprint is compared case- and separator-insensitively, so an operator can
// paste openssl's colon-separated uppercase output.
func TestVerifyPin(t *testing.T) {
	der := []byte("pretend this is a certificate")
	sum := sha256.Sum256(der)
	pin := hex.EncodeToString(sum[:])

	if err := VerifyPin(pin, [][]byte{der}); err != nil {
		t.Fatalf("matching certificate rejected: %v", err)
	}
	if err := VerifyPin(strings.ToUpper(colonize(pin)), [][]byte{der}); err != nil {
		t.Fatalf("openssl-style fingerprint rejected: %v", err)
	}
	if err := VerifyPin(pin, [][]byte{[]byte("another certificate")}); err == nil {
		t.Fatal("a different certificate was accepted")
	}
	if err := VerifyPin(pin, nil); err == nil {
		t.Fatal("no certificate at all was accepted")
	}
}

func colonize(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

// An https host without a pin and without a CA file still verifies against the
// system roots; a plain-http host keeps the shared client.
func TestClientForPicksVerification(t *testing.T) {
	if err := ConfigureTLS("", false, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if got := clientFor(&events.Host{URL: "http://h:7700"}); got != httpClient {
		t.Fatal("a plain-http host should use the shared client")
	}
	c := clientFor(&events.Host{URL: "https://h:7700", TLSFingerprint: "abc"})
	tr := c.Transport.(*http.Transport)
	if tr.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("a pinned host must verify the pin")
	}
	if c2 := clientFor(&events.Host{URL: "https://h:7700", TLSFingerprint: "abc"}); c2 != c {
		t.Fatal("clients should be cached per fingerprint")
	}
	if err := ConfigureTLS("/nonexistent/ca.pem", false, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("an unreadable CA file must be a startup error")
	}
}

// A forwarded exec runs up to execTimeout; the shared client's deadline used to
// end it at 10 s whatever the command (2026-10-08). The client's deadline is
// shrunk here so the test takes milliseconds, not seconds.
func TestAForwardedExecOutlivesTheSharedClientDeadline(t *testing.T) {
	old := httpClient.Timeout
	httpClient.Timeout = 50 * time.Millisecond
	defer func() { httpClient.Timeout = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	h := &events.Host{ID: "h", URL: srv.URL}
	if status, _, err := ForwardExec(context.Background(), h, "s", "sbx_1", []byte(`{}`), "", ""); err != nil || status != http.StatusOK {
		t.Fatalf("a 200 ms exec under its 120 s deadline: %d %v", status, err)
	}
	if _, _, err := do(context.Background(), h, "s", http.MethodGet, "/metrics", nil, 0, nil); err == nil {
		t.Fatal("a call with no deadline of its own keeps the shared client's")
	}
}
