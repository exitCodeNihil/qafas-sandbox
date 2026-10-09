// Package registry implements POST /api/sandboxes: pick a host able to serve the
// requested isolation tier, forward the create request to its qafas, and let the
// caller persist the result.
package registry

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/store"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// How the control plane verifies a qafas certificate (docs/security.md M31),
// in priority order: an explicit CA file, else the fingerprint the host presented
// at registration, else the system roots. SBX_TLS_INSECURE=1 skips all of it.
var (
	caPool      *x509.CertPool
	tlsInsecure bool
	tlsClients  = &sync.Map{} // fingerprint -> *http.Client
)

// ConfigureTLS is called once at startup. A CA file that cannot be read is a
// startup error, not a silent fallback to the system roots.
func ConfigureTLS(caFile string, insecure bool, log *slog.Logger) error {
	caPool, tlsInsecure, tlsClients = nil, insecure, &sync.Map{}
	if insecure {
		log.Warn("SBX_TLS_INSECURE=1: qafas certificates are NOT verified; every remote connection is open to interception. Never set this outside a dev box.")
	}
	if caFile == "" {
		return nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("SBX_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return fmt.Errorf("SBX_CA_FILE %s: no certificate found", caFile)
	}
	caPool = pool
	log.Info("qafas certificates verified against SBX_CA_FILE", "ca_file", caFile)
	return nil
}

// clientFor returns the HTTP client to talk to one host with. Plain-HTTP hosts keep
// the shared client; HTTPS hosts get one per pinned fingerprint, cached.
func clientFor(h *events.Host) *http.Client {
	if !strings.HasPrefix(h.URL, "https://") {
		return httpClient
	}
	if c, ok := tlsClients.Load(h.TLSFingerprint); ok {
		return c.(*http.Client)
	}
	c := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfigFor(h.TLSFingerprint)},
	}
	tlsClients.Store(h.TLSFingerprint, c)
	return c
}

func tlsConfigFor(fingerprint string) *tls.Config {
	switch {
	case tlsInsecure:
		return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // dev only, logged loudly
	case caPool != nil:
		return &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}
	case fingerprint != "":
		// Pinning replaces chain and name verification: the certificate the host
		// registered with is the only one that may answer for it.
		return &tls.Config{
			InsecureSkipVerify:    true, //nolint:gosec // replaced by VerifyPeerCertificate below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error { return VerifyPin(fingerprint, raw) },
		}
	default:
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
}

// VerifyPin reports whether the leaf certificate is the pinned one.
func VerifyPin(fingerprint string, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("qafas presented no certificate")
	}
	sum := sha256.Sum256(rawCerts[0])
	got := hex.EncodeToString(sum[:])
	want := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	if got != want {
		return fmt.Errorf("qafas certificate %s does not match the pinned %s", got, want)
	}
	return nil
}

// HostStaleAfter is how long since a host's last heartbeat before it's reported "stale"
// on GET /metrics and dropped from GET /api/prometheus/targets (docs/protocol.md §4 v4).
// qafas heartbeats every 10s (crates/qafas/src/events.rs); 3x that tolerates one
// missed beat without flapping on jitter alone.
const HostStaleAfter = 30 * time.Second

// HostState reports "live" or "stale" for h as of now.
func HostState(h events.Host, now time.Time) string {
	t, err := time.Parse(time.RFC3339Nano, h.LastSeen)
	if err != nil || now.Sub(t) > HostStaleAfter {
		return "stale"
	}
	return "live"
}

// PlacementError is a placement failure with the exact HTTP status and message the
// caller (handleCreateSandbox) writes back verbatim (docs/protocol.md §4 v4, §4b).
type PlacementError struct {
	Status int
	Msg    string
}

func (e *PlacementError) Error() string { return e.Msg }

// SnapshotHostTimeout bounds how long placement (and GET /api/snapshots[/name]) waits on
// any one host.
const SnapshotHostTimeout = 3 * time.Second

// autoOrder is the auto-resolution order (docs/decisions.md D25: Firecracker first).
// "untrusted" never resolves to native.
func autoOrder(trust string) []string {
	if trust == events.TrustUntrusted {
		return []string{events.IsolationRemote, events.IsolationVm}
	}
	return []string{events.IsolationRemote, events.IsolationVm, events.IsolationNative}
}

// PickHostForRequest chooses a host for req, honoring allowed — the calling API key's
// AllowedTiers, or empty for admin/an unrestricted key (docs/protocol.md §4b).
//
// isolation/trust are normalised (aliases accepted; an unknown value is the caller's job
// to have already rejected via validateCreate, and is treated as auto/trusted here). An
// explicit tier outside allowed is a 403 *PlacementError. An explicit tier needs a host
// advertising it, or a 409. "auto" tries remote, vm, native in order (D25; untrusted drops
// native), restricted to allowed when set, and takes the first tier with a host, or a 409.
// When req.Template names a snapshot (not "base"), candidates are narrowed to hosts
// reporting it "active" (queried in parallel), or a 409 naming every host's state.
// v5 (docs/protocol.md §3a): candidates are then narrowed again to hosts where
// committed + requested <= caps * overcommit, or a 503 (see filterByFit). Among the
// survivors, the host with the most free warm-pool capacity wins.
func PickHostForRequest(ctx context.Context, s *store.Store, req events.CreateSandboxReq, allowed []string, tokenSecret string, requested events.SandboxLimits, overcommitCPU, overcommitMem float64) (*events.Host, string, error) {
	tier, ok := events.NormalizeIsolation(req.Isolation)
	if !ok {
		tier = events.IsolationAuto
	}
	trust, ok := events.NormalizeTrust(req.Trust)
	if !ok {
		trust = events.TrustTrusted
	}

	if len(allowed) > 0 && tier != events.IsolationAuto && !slices.Contains(allowed, tier) {
		return nil, "", &PlacementError{Status: http.StatusForbidden, Msg: fmt.Sprintf("this key may use tiers %v", allowed)}
	}

	hosts, err := s.ListHosts(ctx)
	if err != nil {
		return nil, "", err
	}
	// A host that stopped heartbeating is not a candidate: "auto" prefers remote, so one
	// dead remote host would otherwise 502 every request while a live vm host sits idle.
	hosts = slices.DeleteFunc(hosts, func(h events.Host) bool { return HostState(h, time.Now()) != "live" })

	var matches []events.Host
	var resolved string
	if tier != events.IsolationAuto {
		matches = FilterByTier(hosts, tier)
		if len(matches) == 0 {
			return nil, "", &PlacementError{Status: http.StatusConflict, Msg: fmt.Sprintf("no host serves the %s runtime", tier)}
		}
		resolved = tier
	} else {
		order := autoOrder(trust)
		for _, t := range order {
			if len(allowed) > 0 && !slices.Contains(allowed, t) {
				continue
			}
			if ms := FilterByTier(hosts, t); len(ms) > 0 {
				matches, resolved = ms, t
				break
			}
		}
		if resolved == "" {
			return nil, "", &PlacementError{Status: http.StatusConflict, Msg: fmt.Sprintf("no host serves any of %v", order)}
		}
	}

	if req.Template != "" && req.Template != "base" {
		matches, err = filterBySnapshot(ctx, hosts, matches, tokenSecret, resolved, req.Template)
		if err != nil {
			return nil, "", err
		}
	}

	committed, err := s.CommittedByHost(ctx)
	if err != nil {
		return nil, "", err
	}
	fitting, best := filterByFit(matches, committed, requested, overcommitCPU, overcommitMem)
	if len(fitting) == 0 {
		return nil, "", &PlacementError{Status: http.StatusServiceUnavailable, Msg: fmt.Sprintf(
			"no host has %v cpus / %d MiB free (best: %s %v cpus / %d MiB)",
			requested.Cpus, requested.MemMiB, best.hostID, best.freeCpus, best.freeMemMiB)}
	}

	return mostFreePool(fitting), resolved, nil
}

// hostFree is one candidate's free capacity, tracked only to build the 503 message's
// "best" hint when nothing fits.
type hostFree struct {
	hostID     string
	freeCpus   float64
	freeMemMiB int64 // may be negative when already over-committed; shown as-is
}

// filterByFit narrows hosts to those with committed+requested <= caps*overcommit
// (docs/protocol.md §4 v5). A host with no registered caps (caps.cpus==0 && caps.mem_mib
// ==0: a pre-v4c registration that never sent them) is treated as unlimited and always
// fits, logged once per call so an operator notices the gap.
func filterByFit(hosts []events.Host, committed map[string]events.HostCommitted, requested events.SandboxLimits, overcommitCPU, overcommitMem float64) (fit []events.Host, best hostFree) {
	haveBest := false
	for i := range hosts {
		h := hosts[i]
		if h.Caps.CPUs == 0 && h.Caps.MemMiB == 0 {
			slog.Default().Info("host has no registered capacity; treating as unlimited for placement", "host_id", h.ID)
			fit = append(fit, h)
			continue
		}
		c := committed[h.ID]
		freeCpus := float64(h.Caps.CPUs)*overcommitCPU - c.Cpus
		freeMemMiB := int64(float64(h.Caps.MemMiB)*overcommitMem) - int64(c.MemMiB)
		if freeCpus >= requested.Cpus && freeMemMiB >= int64(requested.MemMiB) {
			fit = append(fit, h)
		}
		if !haveBest || freeMemMiB > best.freeMemMiB {
			best, haveBest = hostFree{hostID: h.ID, freeCpus: freeCpus, freeMemMiB: freeMemMiB}, true
		}
	}
	return fit, best
}

// fanout runs fn concurrently for every host and returns the results in the same order as
// hosts (each goroutine writes only its own slot, so no mutex is needed).
func fanout[T any](hosts []events.Host, fn func(h events.Host) T) []T {
	out := make([]T, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h events.Host) {
			defer wg.Done()
			out[i] = fn(h)
		}(i, h)
	}
	wg.Wait()
	return out
}

// filterBySnapshot narrows hosts to those reporting template "active" (docs/protocol.md
// §4 v4), querying every host in parallel (SnapshotHostTimeout each, reusing
// ListSnapshotsOnHost). A host that doesn't have the name at all, or that errors, counts
// as "missing" in the 409 message.
func filterBySnapshot(ctx context.Context, all, candidates []events.Host, tokenSecret, tier, template string) ([]events.Host, error) {
	// Every host is asked (not only the tier's candidates) so a name that exists
	// nowhere is a 404 like the daemon's own answer, while a name that exists on
	// a host of another tier, or is still building here, is a 409 naming hosts.
	stateList := fanout(all, func(h events.Host) string {
		if list, err := ListSnapshotsOnHost(ctx, &h, tokenSecret, SnapshotHostTimeout); err == nil {
			for _, si := range list {
				if si.Name == template {
					return si.State
				}
			}
		}
		return "missing"
	})
	states := make(map[string]string, len(all))
	for i, h := range all {
		states[h.ID] = stateList[i]
	}

	var out []events.Host
	for _, h := range candidates {
		if states[h.ID] == "active" {
			out = append(out, h)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	known := false
	parts := make([]string, 0, len(all))
	for _, h := range all {
		if states[h.ID] != "missing" {
			known = true
		}
		parts = append(parts, h.ID+"="+states[h.ID])
	}
	if !known {
		return nil, &PlacementError{Status: http.StatusNotFound, Msg: fmt.Sprintf("unknown template %q", template)}
	}
	return nil, &PlacementError{Status: http.StatusConflict, Msg: fmt.Sprintf("snapshot %q is not active on any %s host: %s", template, tier, strings.Join(parts, ", "))}
}

// FilterByTier returns the hosts whose Tiers include tier. Shared by PickHostForRequest
// (sandbox placement) and the snapshot handlers' runtime fan-out (docs/protocol.md §3a
// v4c: "The control plane fans the build out to hosts advertising that runtime only").
func FilterByTier(hosts []events.Host, tier string) []events.Host {
	var out []events.Host
	for _, h := range hosts {
		if slices.Contains(h.Tiers, tier) {
			out = append(out, h)
		}
	}
	return out
}

func mostFreePool(hosts []events.Host) *events.Host {
	best := slices.MaxFunc(hosts, func(a, b events.Host) int { return cmp.Compare(freePool(a), freePool(b)) })
	return &best
}

func freePool(h events.Host) uint32 {
	var total uint32
	for _, p := range h.Pool {
		total += p.Warm
	}
	return total
}

// UpstreamError is a non-201 reply from a qafas daemon, carrying its exact status and
// body so the caller can relay them unchanged (docs/protocol.md §4 v4: "passes the
// daemon's status and body through unchanged").
type UpstreamError struct {
	Status int
	Body   []byte
}

func (e *UpstreamError) Error() string { return string(e.Body) }

// Acquire forwards the create request to the chosen host's qafas. `client` is the
// caller's X-Sbx-Client, passed on so the host log attributes the sandbox to the harness
// that asked for it rather than to the control plane (docs/security.md M33).
func Acquire(ctx context.Context, host *events.Host, tokenSecret, client string, req events.CreateSandboxReq) (*events.CreateSandboxResp, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, host.URL+"/sandboxes", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+tokenSecret)
	if client == "" {
		client = "controlplane"
	}
	httpReq.Header.Set("X-Sbx-Client", client)

	// A create may include a cold microVM boot or a snapshot restore; the 10 s
	// shared timeout is for chatty calls. Same transport, longer deadline.
	c := *clientFor(host)
	c.Timeout = 120 * time.Second
	resp, err := c.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("qafas %s: %w", host.ID, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return nil, &UpstreamError{Status: resp.StatusCode, Body: respBody}
	}
	var out events.CreateSandboxResp
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	out.HostID = host.ID
	// The host row is the authority on which certificate is pinned for this host,
	// so pi pins what the control plane pinned rather than what the reply claims.
	if host.TLSFingerprint != "" {
		out.TLSFingerprint = host.TLSFingerprint
	}
	return &out, nil
}

// do issues one authenticated request to host and returns its status and raw body — the
// mechanics (URL, auth header, pinned-TLS client, optional deadline) shared by every
// forwarder below. timeout <= 0 keeps ctx as given (the shared client's own 10s applies);
// extraHeaders lets ForwardExec add the correlation headers without its own copy of this.
func do(ctx context.Context, host *events.Host, tokenSecret, method, path string, body []byte, timeout time.Duration, extraHeaders map[string]string) (status int, respBody []byte, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, host.URL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tokenSecret)
	for k, v := range extraHeaders {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	// The shared client's 10 s deadline is for chatty calls; a call that brings its
	// own longer one (a forwarded exec) must not be cut off by it.
	c := clientFor(host)
	if timeout > c.Timeout {
		long := *c
		long.Timeout = timeout
		c = &long
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("qafas %s: %w", host.ID, err)
	}
	defer resp.Body.Close()
	respBody, _ = io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

// Destroy forwards DELETE /sandboxes/{id} to the owning host. A 404 there means the
// sandbox is already gone, which is the outcome the caller wanted.
func Destroy(ctx context.Context, host *events.Host, tokenSecret, sandboxID string) error {
	status, body, err := do(ctx, host, tokenSecret, http.MethodDelete, "/sandboxes/"+sandboxID, nil, 0, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("qafas %s: %d: %s", host.ID, status, string(body))
	}
	return nil
}

// ProxyProcesses forwards GET /sandboxes/{id}/processes to the owning host's qafas,
// returning the raw response body and status code (502 with a JSON error if unreachable
// is the caller's job to write, since this just surfaces the error).
func ProxyProcesses(ctx context.Context, host *events.Host, tokenSecret, sandboxID string) (status int, body []byte, err error) {
	return do(ctx, host, tokenSecret, http.MethodGet, "/sandboxes/"+sandboxID+"/processes", nil, 0, nil)
}

// FetchMetrics forwards GET /metrics to host's qafas, for GET /api/hosts/{id}/metrics
// (docs/protocol.md §4 v4). Same pinned-TLS client every other forwarded request uses.
func FetchMetrics(ctx context.Context, host *events.Host, tokenSecret string) (status int, body []byte, err error) {
	return do(ctx, host, tokenSecret, http.MethodGet, "/metrics", nil, 0, nil)
}

// TransportFor returns the RoundTripper that reaches host with the same TLS pinning as
// every other forwarded request (nil means the default transport, fine for plain HTTP
// hosts) — used by the /preview/{id}/{port}/{*rest} reverse proxy, which needs its own
// http.Transport rather than the shared *http.Client the helpers above use.
func TransportFor(host *events.Host) http.RoundTripper {
	if !strings.HasPrefix(host.URL, "https://") {
		return nil
	}
	return clientFor(host).Transport
}

// ---- v3: lifecycle, preview, snapshots

// ForwardLifecycle forwards POST /sandboxes/{id}/{stop,start,pause,resume,archive} to the
// owning host, relaying status and body verbatim (204 for stop/pause/resume/archive, 200
// SandboxInfo for start, or the daemon's error body/status on failure).
func ForwardLifecycle(ctx context.Context, host *events.Host, tokenSecret, sandboxID, verb string) (status int, body []byte, err error) {
	return do(ctx, host, tokenSecret, http.MethodPost, "/sandboxes/"+sandboxID+"/"+verb, nil, 0, nil)
}

// execTimeout: the daemon wakes a stopped sandbox itself (transparent start, §3a v4)
// before serving the exec, and the command itself may run long.
const execTimeout = 120 * time.Second

// ForwardExec forwards POST /api/sandboxes/{id}/exec to the owning host's
// /sandboxes/{id}/agent/exec (qafas's proxy into guest-agent's POST /exec,
// docs/protocol.md §4a), passing the caller's correlation headers through (§7) and
// relaying status/body verbatim.
func ForwardExec(ctx context.Context, host *events.Host, tokenSecret, sandboxID string, body []byte, piSession, toolCallID string) (status int, respBody []byte, err error) {
	headers := map[string]string{events.HdrPiSession: piSession, events.HdrToolCallID: toolCallID}
	return do(ctx, host, tokenSecret, http.MethodPost, "/sandboxes/"+sandboxID+"/agent/exec", body, execTimeout, headers)
}

// ForwardPreview forwards POST /sandboxes/{id}/preview to the owning host.
func ForwardPreview(ctx context.Context, host *events.Host, tokenSecret, sandboxID string, preq events.CreatePreviewReq) (status int, body []byte, err error) {
	b, err := json.Marshal(preq)
	if err != nil {
		return 0, nil, err
	}
	return do(ctx, host, tokenSecret, http.MethodPost, "/sandboxes/"+sandboxID+"/preview", b, 0, nil)
}

// CreateSnapshotOnHost forwards POST /snapshots to one host.
func CreateSnapshotOnHost(ctx context.Context, host *events.Host, tokenSecret string, req events.CreateSnapshotReq) (*events.SnapshotInfo, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	status, body, err := do(ctx, host, tokenSecret, http.MethodPost, "/snapshots", b, 0, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusAccepted {
		return nil, fmt.Errorf("qafas %s: %d: %s", host.ID, status, string(body))
	}
	var info events.SnapshotInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	info.HostID = host.ID
	return &info, nil
}

// ListSnapshotsOnHost forwards GET /snapshots to one host with the given timeout.
func ListSnapshotsOnHost(ctx context.Context, host *events.Host, tokenSecret string, timeout time.Duration) ([]events.SnapshotInfo, error) {
	status, body, err := do(ctx, host, tokenSecret, http.MethodGet, "/snapshots", nil, timeout, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("qafas %s: %d: %s", host.ID, status, string(body))
	}
	var list []events.SnapshotInfo
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	for i := range list {
		list[i].HostID = host.ID
	}
	return list, nil
}

// GetSnapshotOnHost forwards GET /snapshots/{name} to one host. A 404 there is not an
// error: it returns (nil, nil), meaning "this host doesn't have it".
func GetSnapshotOnHost(ctx context.Context, host *events.Host, tokenSecret, name string, timeout time.Duration) (*events.SnapshotInfo, error) {
	status, body, err := do(ctx, host, tokenSecret, http.MethodGet, "/snapshots/"+name, nil, timeout, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("qafas %s: %d: %s", host.ID, status, string(body))
	}
	var info events.SnapshotInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	info.HostID = host.ID
	return &info, nil
}

// UpdateSnapshotOnHost forwards PUT /snapshots/{name} ({"warm": n}) to one host.
func UpdateSnapshotOnHost(ctx context.Context, host *events.Host, tokenSecret, name string, req events.UpdateSnapshotReq) (*events.SnapshotInfo, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	status, body, err := do(ctx, host, tokenSecret, http.MethodPut, "/snapshots/"+name, b, 0, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("qafas %s: %d: %s", host.ID, status, string(body))
	}
	var info events.SnapshotInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	info.HostID = host.ID
	return &info, nil
}

// ScanSnapshotOnHost forwards POST /snapshots/{name}/scan (v5.2) to one host. The daemon
// answers 202 with the row as it is and scans in the background.
func ScanSnapshotOnHost(ctx context.Context, host *events.Host, tokenSecret, name string) (*events.SnapshotInfo, error) {
	status, body, err := do(ctx, host, tokenSecret, http.MethodPost, "/snapshots/"+name+"/scan", nil, 0, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusAccepted {
		return nil, fmt.Errorf("qafas %s: %d: %s", host.ID, status, string(body))
	}
	var info events.SnapshotInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	info.HostID = host.ID
	return &info, nil
}

// DeleteSnapshotOnHost forwards DELETE /snapshots/{name} to one host. A 404 there means
// the host never had it, which is the outcome the caller wanted. Any other non-2xx status
// (in particular 409 "in use by sbx_…") comes back as *UpstreamError, so the caller
// (handleDeleteSnapshot) can tell a daemon-side refusal apart from a transport failure and
// relay the daemon's own status/body instead of always wrapping it as 502.
func DeleteSnapshotOnHost(ctx context.Context, host *events.Host, tokenSecret, name string) error {
	status, body, err := do(ctx, host, tokenSecret, http.MethodDelete, "/snapshots/"+name, nil, 0, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return &UpstreamError{Status: status, Body: body}
	}
	return nil
}
