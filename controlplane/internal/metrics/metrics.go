// Package metrics renders the control plane's own `GET /metrics` Prometheus text page
// (docs/protocol.md §4 v4, docs/decisions.md D24: hand-rolled text, no client library —
// same spirit as crates/qafas/src/metrics.rs, which this mirrors in shape).
//
// Counters (events/alerts ingested, HTTP requests/latency) are kept in-process by the
// Collector, hooked from the code paths that already see them. Gauges (hosts, sandboxes,
// api keys, db size) are computed at scrape time from the store by the caller and passed
// in via Gauges, so they can't drift from what the store actually holds.
package metrics

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

// httpBuckets are upper bounds in milliseconds for sbxcp_http_request_duration_ms. No
// route/method label on the histogram itself (unlike the _total counter): a handful of
// global buckets is enough to see whether the control plane is slow at all, and avoids
// multiplying bucket cardinality by route count.
var httpBuckets = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// connBuckets are upper bounds in seconds for sbxcp_connection_seconds — the SSE stream and
// preview-websocket routes, timed separately from httpBuckets so a connection open for
// minutes doesn't skew the sub-second HTTP histogram.
var connBuckets = []float64{1, 5, 15, 30, 60, 300, 900, 3600}

type ruleSeverity struct{ rule, severity string }
type routeCode struct{ route, code string }

// SandboxKey groups the sbxcp_sandboxes gauge (docs/protocol.md §4 v4).
type SandboxKey struct{ HostID, Tier, State string }

// Gauges is everything the caller can only know at scrape time, read fresh from the store
// and the registry rather than tracked incrementally.
type Gauges struct {
	HostsLive, HostsStale int
	Sandboxes             map[SandboxKey]int
	ApiKeySandboxes       map[string]int // api key name -> live sandbox count
	DBBytes               int64
	// v5 (docs/protocol.md §4 v4 metrics row): host_id -> its registered caps/committed.
	// Populated from the same host list, so the two maps share exactly the same keys.
	HostCaps      map[string]events.HostCaps
	HostCommitted map[string]events.HostCommitted
	// SSEDropped is events.Hub.Dropped: SSE/stream events dropped because a subscriber's
	// buffer was full (sbxcp_sse_dropped_total).
	SSEDropped uint64
}

// Collector counts events/alerts ingested and HTTP requests served — the two things the
// control plane can only know from inside itself, not from a scrape-time store read.
type Collector struct {
	mu     sync.Mutex
	events map[string]uint64
	alerts map[ruleSeverity]uint64

	httpMu     sync.Mutex
	httpTotal  map[routeCode]uint64
	httpBucket []uint64 // cumulative counts, parallel to httpBuckets
	httpCount  uint64
	httpSumMs  float64

	connMu     sync.Mutex
	connBucket []uint64 // cumulative counts, parallel to connBuckets
	connCount  uint64
	connSumS   float64
}

func New() *Collector {
	return &Collector{
		events:     map[string]uint64{},
		alerts:     map[ruleSeverity]uint64{},
		httpTotal:  map[routeCode]uint64{},
		httpBucket: make([]uint64, len(httpBuckets)),
		connBucket: make([]uint64, len(connBuckets)),
	}
}

// ObserveEvent is hooked from POST /api/events (both the ingested batch and any
// deny-burst alert the ingest handler generated), so sbxcp_events_total/sbxcp_alerts_total
// can't drift from what was actually stored.
func (c *Collector) ObserveEvent(e events.Event) {
	c.mu.Lock()
	c.events[e.Type]++
	c.mu.Unlock()
	if e.Type != events.SecurityAlert {
		return
	}
	var ad events.AlertData
	if json.Unmarshal(e.Data, &ad) != nil {
		return
	}
	rule, sev := ad.Rule, ad.Severity
	if rule == "" {
		rule = "unknown"
	}
	if sev == "" {
		sev = "unknown"
	}
	c.mu.Lock()
	c.alerts[ruleSeverity{rule, sev}]++
	c.mu.Unlock()
}

// ObserveHTTP is hooked from the top-level HTTP middleware (api.API.HTTPMiddleware) for
// every request.
func (c *Collector) ObserveHTTP(route string, code int, dur time.Duration) {
	c.httpMu.Lock()
	defer c.httpMu.Unlock()
	c.httpTotal[routeCode{route, strconv.Itoa(code)}]++
	ms := float64(dur.Microseconds()) / 1000.0
	// Cumulative at observe time (mirrors crates/qafas/src/metrics.rs): every bucket
	// whose bound is >= this observation gets +1, so render just prints the counts.
	for i, b := range httpBuckets {
		if ms <= b {
			c.httpBucket[i]++
		}
	}
	c.httpCount++
	c.httpSumMs += ms
}

// ObserveConnection is hooked from HTTPMiddleware for long-lived connections (the SSE
// stream, the preview websocket proxy) instead of ObserveHTTP, so sbxcp_http_request_
// duration_ms's sub-second buckets aren't skewed by a connection open for minutes.
func (c *Collector) ObserveConnection(dur time.Duration) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	s := dur.Seconds()
	for i, bnd := range connBuckets {
		if s <= bnd {
			c.connBucket[i]++
		}
	}
	c.connCount++
	c.connSumS += s
}

// Render is the full Prometheus text exposition: this Collector's in-process counters
// plus the caller-supplied Gauges and Go runtime stats.
func (c *Collector) Render(g Gauges, version string) string {
	var b strings.Builder
	b.Grow(4096)
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	b.WriteString("# HELP sbxcp_hosts Registered hosts by liveness.\n# TYPE sbxcp_hosts gauge\n")
	line(`sbxcp_hosts{state="live"} %d`, g.HostsLive)
	line(`sbxcp_hosts{state="stale"} %d`, g.HostsStale)

	b.WriteString("# HELP sbxcp_sandboxes Sandbox rows by host, tier and state.\n# TYPE sbxcp_sandboxes gauge\n")
	for _, k := range sortedSandboxKeys(g.Sandboxes) {
		line(`sbxcp_sandboxes{host_id="%s",tier="%s",state="%s"} %d`, esc(k.HostID), esc(k.Tier), esc(k.State), g.Sandboxes[k])
	}

	c.mu.Lock()
	b.WriteString("# HELP sbxcp_events_total Events ingested, by type.\n# TYPE sbxcp_events_total counter\n")
	for _, ty := range slices.Sorted(maps.Keys(c.events)) {
		line(`sbxcp_events_total{type="%s"} %d`, esc(ty), c.events[ty])
	}
	b.WriteString("# HELP sbxcp_alerts_total Security alerts ingested, by rule and severity.\n# TYPE sbxcp_alerts_total counter\n")
	for _, k := range sortedRuleSeverity(c.alerts) {
		line(`sbxcp_alerts_total{rule="%s",severity="%s"} %d`, esc(k.rule), esc(k.severity), c.alerts[k])
	}
	c.mu.Unlock()

	c.httpMu.Lock()
	b.WriteString("# HELP sbxcp_http_requests_total HTTP requests, by mux route and status code.\n# TYPE sbxcp_http_requests_total counter\n")
	for _, k := range sortedRouteCode(c.httpTotal) {
		line(`sbxcp_http_requests_total{route="%s",code="%s"} %d`, esc(k.route), k.code, c.httpTotal[k])
	}
	b.WriteString("# HELP sbxcp_http_request_duration_ms HTTP request duration.\n# TYPE sbxcp_http_request_duration_ms histogram\n")
	for i, bound := range httpBuckets {
		line(`sbxcp_http_request_duration_ms_bucket{le="%s"} %d`, formatFloat(bound), c.httpBucket[i])
	}
	line(`sbxcp_http_request_duration_ms_bucket{le="+Inf"} %d`, c.httpCount)
	line(`sbxcp_http_request_duration_ms_sum %s`, formatFloat(c.httpSumMs))
	line(`sbxcp_http_request_duration_ms_count %d`, c.httpCount)
	c.httpMu.Unlock()

	c.connMu.Lock()
	b.WriteString("# HELP sbxcp_connection_seconds Duration of long-lived connections (SSE stream, preview websocket).\n# TYPE sbxcp_connection_seconds histogram\n")
	for i, bnd := range connBuckets {
		line(`sbxcp_connection_seconds_bucket{le="%s"} %d`, formatFloat(bnd), c.connBucket[i])
	}
	line(`sbxcp_connection_seconds_bucket{le="+Inf"} %d`, c.connCount)
	line(`sbxcp_connection_seconds_sum %s`, formatFloat(c.connSumS))
	line(`sbxcp_connection_seconds_count %d`, c.connCount)
	c.connMu.Unlock()

	b.WriteString("# HELP sbxcp_api_key_sandboxes_total Live sandboxes per API key.\n# TYPE sbxcp_api_key_sandboxes_total gauge\n")
	for _, name := range slices.Sorted(maps.Keys(g.ApiKeySandboxes)) {
		line(`sbxcp_api_key_sandboxes_total{key="%s"} %d`, esc(name), g.ApiKeySandboxes[name])
	}

	b.WriteString("# HELP sbxcp_db_bytes Size of the sqlite database file.\n# TYPE sbxcp_db_bytes gauge\n")
	line(`sbxcp_db_bytes %d`, g.DBBytes)

	b.WriteString("# HELP sbxcp_sse_dropped_total Events dropped for a slow SSE/stream subscriber.\n# TYPE sbxcp_sse_dropped_total counter\n")
	line(`sbxcp_sse_dropped_total %d`, g.SSEDropped)

	b.WriteString("# HELP sbxcp_host_capacity_cpus Registered host CPU capacity.\n# TYPE sbxcp_host_capacity_cpus gauge\n")
	for _, id := range slices.Sorted(maps.Keys(g.HostCaps)) {
		line(`sbxcp_host_capacity_cpus{host_id="%s"} %d`, esc(id), g.HostCaps[id].CPUs)
	}
	b.WriteString("# HELP sbxcp_host_capacity_mem_mib Registered host memory capacity.\n# TYPE sbxcp_host_capacity_mem_mib gauge\n")
	for _, id := range slices.Sorted(maps.Keys(g.HostCaps)) {
		line(`sbxcp_host_capacity_mem_mib{host_id="%s"} %d`, esc(id), g.HostCaps[id].MemMiB)
	}
	b.WriteString("# HELP sbxcp_host_committed_cpus Committed vCPUs of a host's live sandboxes.\n# TYPE sbxcp_host_committed_cpus gauge\n")
	for _, id := range slices.Sorted(maps.Keys(g.HostCaps)) {
		line(`sbxcp_host_committed_cpus{host_id="%s"} %s`, esc(id), formatFloat(g.HostCommitted[id].Cpus))
	}
	b.WriteString("# HELP sbxcp_host_committed_mem_mib Committed memory of a host's live sandboxes.\n# TYPE sbxcp_host_committed_mem_mib gauge\n")
	for _, id := range slices.Sorted(maps.Keys(g.HostCaps)) {
		line(`sbxcp_host_committed_mem_mib{host_id="%s"} %d`, esc(id), g.HostCommitted[id].MemMiB)
	}

	b.WriteString("# HELP sbxcp_build_info Build metadata.\n# TYPE sbxcp_build_info gauge\n")
	line(`sbxcp_build_info{version="%s"} 1`, esc(version))

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	b.WriteString("# HELP go_goroutines Number of goroutines that currently exist.\n# TYPE go_goroutines gauge\n")
	line(`go_goroutines %d`, runtime.NumGoroutine())
	b.WriteString("# HELP go_memstats_alloc_bytes Bytes allocated and still in use.\n# TYPE go_memstats_alloc_bytes gauge\n")
	line(`go_memstats_alloc_bytes %d`, mem.Alloc)
	b.WriteString("# HELP go_memstats_sys_bytes Bytes obtained from the OS.\n# TYPE go_memstats_sys_bytes gauge\n")
	line(`go_memstats_sys_bytes %d`, mem.Sys)
	b.WriteString("# HELP go_gc_total Number of completed GC cycles.\n# TYPE go_gc_total counter\n")
	line(`go_gc_total %d`, mem.NumGC)

	return b.String()
}

// BuildVersion is the control plane binary's version for sbxcp_build_info, from Go's own
// module build info (docs/protocol.md §4 v4: "version from debug.ReadBuildInfo or a
// -ldflags var" — this is the zero-plumbing option).
func BuildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

// escReplacer matches crates/qafas/src/metrics.rs's escaping: label values come from host
// ids, rule names and api key names, but a stray quote/backslash/newline must not be able
// to break the exposition format.
var escReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", " ")

func esc(v string) string { return escReplacer.Replace(v) }

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func sortedRuleSeverity(m map[ruleSeverity]uint64) []ruleSeverity {
	return slices.SortedFunc(maps.Keys(m), func(a, b ruleSeverity) int {
		return cmp.Or(cmp.Compare(a.rule, b.rule), cmp.Compare(a.severity, b.severity))
	})
}

func sortedRouteCode(m map[routeCode]uint64) []routeCode {
	return slices.SortedFunc(maps.Keys(m), func(a, b routeCode) int {
		return cmp.Or(cmp.Compare(a.route, b.route), cmp.Compare(a.code, b.code))
	})
}

func sortedSandboxKeys(m map[SandboxKey]int) []SandboxKey {
	return slices.SortedFunc(maps.Keys(m), func(a, b SandboxKey) int {
		return cmp.Or(cmp.Compare(a.HostID, b.HostID), cmp.Compare(a.Tier, b.Tier), cmp.Compare(a.State, b.State))
	})
}
