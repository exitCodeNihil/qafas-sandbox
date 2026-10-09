package metrics

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

func TestCountersAndHistogramRender(t *testing.T) {
	c := New()
	c.ObserveEvent(events.Event{Type: events.ExecStart})
	c.ObserveEvent(events.Event{Type: events.ExecStart})
	c.ObserveEvent(events.Event{Type: events.SecurityAlert, Data: json.RawMessage(`{"rule":"canary.read","severity":"critical"}`)})
	c.ObserveHTTP("GET /api/hosts", 200, 3*time.Millisecond)
	c.ObserveHTTP("GET /api/hosts", 200, 300*time.Millisecond)

	out := c.Render(Gauges{
		HostsLive: 2, HostsStale: 1,
		Sandboxes:       map[SandboxKey]int{{HostID: "h1", Tier: "native", State: "ready"}: 3},
		ApiKeySandboxes: map[string]int{"team-a": 2},
		DBBytes:         12345,
	}, "1.2.3")

	for _, want := range []string{
		`sbxcp_hosts{state="live"} 2`,
		`sbxcp_hosts{state="stale"} 1`,
		`sbxcp_sandboxes{host_id="h1",tier="native",state="ready"} 3`,
		`sbxcp_events_total{type="exec.start"} 2`,
		`sbxcp_alerts_total{rule="canary.read",severity="critical"} 1`,
		`sbxcp_http_requests_total{route="GET /api/hosts",code="200"} 2`,
		// 3ms lands in the 5ms bucket but not below; 300ms lands past the 250ms bucket.
		`sbxcp_http_request_duration_ms_bucket{le="5"} 1`,
		`sbxcp_http_request_duration_ms_bucket{le="250"} 1`,
		`sbxcp_http_request_duration_ms_bucket{le="500"} 2`,
		`sbxcp_http_request_duration_ms_bucket{le="+Inf"} 2`,
		`sbxcp_http_request_duration_ms_count 2`,
		`sbxcp_api_key_sandboxes_total{key="team-a"} 2`,
		`sbxcp_db_bytes 12345`,
		`sbxcp_build_info{version="1.2.3"} 1`,
		"go_goroutines",
		"go_memstats_alloc_bytes",
		"go_memstats_sys_bytes",
		"go_gc_total",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestLabelValuesCannotBreakThePage(t *testing.T) {
	c := New()
	c.ObserveEvent(events.Event{Type: events.SecurityAlert, Data: json.RawMessage(`{"rule":"we\"ird\nrule","severity":"low"}`)})
	out := c.Render(Gauges{}, "dev")
	if !strings.Contains(out, `rule="we\"ird rule"`) {
		t.Fatalf("escaping failed:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "#") || l == "" {
			continue
		}
		if strings.Count(l, "{") > 1 {
			t.Fatalf("label value broke the line into two label sets: %q", l)
		}
	}
}

func TestAlertWithoutFieldsDoesNotPanic(t *testing.T) {
	c := New()
	c.ObserveEvent(events.Event{Type: events.SecurityAlert, Data: json.RawMessage(`{}`)})
	out := c.Render(Gauges{}, "dev")
	if !strings.Contains(out, `severity="unknown"`) {
		t.Fatalf("missing unknown-severity fallback:\n%s", out)
	}
}

func TestBuildVersionNeverEmpty(t *testing.T) {
	if BuildVersion() == "" {
		t.Fatal("BuildVersion must never return an empty string")
	}
}

// v5: host capacity/committed gauges (docs/protocol.md §4 v4 metrics row, "v5:" clause).
func TestHostCapacityAndCommittedGaugesRender(t *testing.T) {
	c := New()
	out := c.Render(Gauges{
		HostCaps:      map[string]events.HostCaps{"mac-local": {CPUs: 4, MemMiB: 4096}},
		HostCommitted: map[string]events.HostCommitted{"mac-local": {Cpus: 2.5, MemMiB: 2560}},
	}, "dev")

	for _, want := range []string{
		`sbxcp_host_capacity_cpus{host_id="mac-local"} 4`,
		`sbxcp_host_capacity_mem_mib{host_id="mac-local"} 4096`,
		`sbxcp_host_committed_cpus{host_id="mac-local"} 2.5`,
		`sbxcp_host_committed_mem_mib{host_id="mac-local"} 2560`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}
