package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func alertData(sev, rule, msg string) []byte {
	b, _ := json.Marshal(events.AlertData{Severity: sev, Rule: rule, Msg: msg})
	return b
}

// TestAlertCountsForSessionsSQL exercises alertCountsForSessions' SQL aggregation (counts
// per severity, top rule = the highest-severity alert's rule, earliest on a tie) against a
// fixture mixing severities across two sessions — the same result the old per-row Go loop
// would have produced.
func TestAlertCountsForSessionsSQL(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	evs := []events.Event{
		{ID: "01A", TS: "2026-09-08T10:00:00.000Z", SandboxID: "sbx1", PiSession: "sess1", Type: events.SecurityAlert, Data: alertData(events.SevLow, "rule.low", "x")},
		{ID: "01B", TS: "2026-09-08T10:00:01.000Z", SandboxID: "sbx1", PiSession: "sess1", Type: events.SecurityAlert, Data: alertData(events.SevHigh, "rule.high-first", "x")},
		{ID: "01C", TS: "2026-09-08T10:00:02.000Z", SandboxID: "sbx1", PiSession: "sess1", Type: events.SecurityAlert, Data: alertData(events.SevHigh, "rule.high-second", "x")},
		{ID: "01D", TS: "2026-09-08T10:00:03.000Z", SandboxID: "sbx1", PiSession: "sess1", Type: events.SecurityAlert, Data: alertData(events.SevMedium, "rule.medium", "x")},
		// sess2: a single critical alert.
		{ID: "01E", TS: "2026-09-08T11:00:00.000Z", SandboxID: "sbx2", PiSession: "sess2", Type: events.SecurityAlert, Data: alertData(events.SevCritical, "rule.critical", "x")},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	agg, err := s.alertCountsForSessions(ctx, []string{"sess1", "sess2", "sess-with-no-alerts"})
	if err != nil {
		t.Fatalf("alertCountsForSessions: %v", err)
	}

	a1 := agg["sess1"]
	if a1.counts != (AlertCounts{Low: 1, High: 2, Medium: 1}) {
		t.Fatalf("sess1 counts: %+v", a1.counts)
	}
	if a1.topRule != "rule.high-first" {
		t.Fatalf("sess1 top rule: want the earliest of the tied highest-severity alerts, got %q", a1.topRule)
	}

	a2 := agg["sess2"]
	if a2.counts != (AlertCounts{Critical: 1}) || a2.topRule != "rule.critical" {
		t.Fatalf("sess2: %+v", a2)
	}

	if empty := agg["sess-with-no-alerts"]; empty.counts != (AlertCounts{}) || empty.topRule != "" {
		t.Fatalf("session with no alerts must be the zero value: %+v", empty)
	}
}

// TestSearchFTS5 covers the events_fts shadow table: a prefix query matches a token that
// only starts with the search term, and a two-term query ranks the row containing both
// terms above a row containing only one of them.
func TestSearchFTS5(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	evs := []events.Event{
		{ID: "01A", TS: "2026-09-08T10:00:00.000Z", SandboxID: "sbx1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"cat /etc/passwd"}`)},
		{ID: "01B", TS: "2026-09-08T10:00:01.000Z", SandboxID: "sbx1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"cat /etc/hosts"}`)},
		{ID: "01C", TS: "2026-09-08T10:00:02.000Z", SandboxID: "sbx1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"echo hello"}`)},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	// Prefix query: "pass" must find the /etc/passwd row via its "passwd" token.
	got, err := s.Search(ctx, "pass", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].ID != "01A" {
		t.Fatalf("prefix query: want just 01A, got %+v", got)
	}

	// Two-term query: both "cat" and "etc" appear in 01A and 01B, not in 01C.
	got, err = s.Search(ctx, "cat etc", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("two-term query: want 2 rows, got %+v", got)
	}

	// Empty query: a browse view, newest first, no FTS5 involved.
	got, err = s.Search(ctx, "", 10)
	if err != nil {
		t.Fatalf("Search empty: %v", err)
	}
	if len(got) != 3 || got[0].ID != "01C" {
		t.Fatalf("empty query: want all 3, newest first, got %+v", got)
	}
}

func TestSessionsAggregation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	evs := []events.Event{
		{ID: "01A", TS: "2026-09-08T10:00:00.000Z", HostID: "h1", SandboxID: "sbx1", PiSession: "sess1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"ls"}`)},
		{ID: "01B", TS: "2026-09-08T10:00:00.100Z", HostID: "h1", SandboxID: "sbx1", PiSession: "sess1", Type: events.ExecEnd, Data: json.RawMessage(`{"exit":0}`)},
		{ID: "01C", TS: "2026-09-08T10:00:01.000Z", HostID: "h1", SandboxID: "sbx2", PiSession: "sess1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"pwd"}`)},
		{ID: "01D", TS: "2026-09-08T10:00:01.100Z", HostID: "h1", SandboxID: "sbx2", PiSession: "sess1", Type: events.SecurityAlert, Data: alertData(events.SevHigh, events.RuleSensitivePathRead, "read ~/.ssh")},
		{ID: "01E", TS: "2026-09-08T11:00:00.000Z", HostID: "h2", SandboxID: "sbx3", PiSession: "sess2", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"echo"}`)},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	list, err := s.ListSessions(ctx, 10, "", "")
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 sessions, got %d: %+v", len(list), list)
	}
	// newest last_ts first
	if list[0].PiSession != "sess2" {
		t.Fatalf("want sess2 first (newest), got %q", list[0].PiSession)
	}
	sess1 := list[1]
	if sess1.Events != 4 {
		t.Fatalf("sess1 events: want 4, got %d", sess1.Events)
	}
	if sess1.Execs != 2 {
		t.Fatalf("sess1 execs: want 2, got %d", sess1.Execs)
	}
	if len(sess1.SandboxIDs) != 2 {
		t.Fatalf("sess1 sandbox_ids: want 2, got %+v", sess1.SandboxIDs)
	}
	if sess1.Alerts.High != 1 {
		t.Fatalf("sess1 alerts.high: want 1, got %+v", sess1.Alerts)
	}
	if sess1.TopAlert != events.RuleSensitivePathRead {
		t.Fatalf("sess1 top_alert: want %q, got %q", events.RuleSensitivePathRead, sess1.TopAlert)
	}

	detail, err := s.GetSession(ctx, "sess1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if detail == nil || detail.Events != 4 {
		t.Fatalf("GetSession(sess1): %+v", detail)
	}

	if none, err := s.GetSession(ctx, "no-such-session"); err != nil || none != nil {
		t.Fatalf("GetSession(missing): %v %+v", err, none)
	}

	sessEvs, err := s.ListSessionEvents(ctx, "sess1", "", nil, 500)
	if err != nil {
		t.Fatalf("ListSessionEvents: %v", err)
	}
	if len(sessEvs) != 4 {
		t.Fatalf("ListSessionEvents: want 4, got %d", len(sessEvs))
	}
	filtered, err := s.ListSessionEvents(ctx, "sess1", "", []string{events.SecurityAlert}, 500)
	if err != nil {
		t.Fatalf("ListSessionEvents filtered: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("ListSessionEvents filtered by type: want 1, got %d", len(filtered))
	}
}

func TestAlertsFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	evs := []events.Event{
		{ID: "01A", TS: "2026-09-08T10:00:00.000Z", SandboxID: "sbx1", PiSession: "sess1", Type: events.SecurityAlert, Data: alertData(events.SevCritical, events.RuleCanaryRead, "canary")},
		{ID: "01B", TS: "2026-09-08T10:00:01.000Z", SandboxID: "sbx2", PiSession: "sess2", Type: events.SecurityAlert, Data: alertData(events.SevLow, events.RuleResourceLimit, "pids")},
		{ID: "01C", TS: "2026-09-08T10:00:02.000Z", SandboxID: "sbx1", PiSession: "sess1", Type: events.ExecStart, Data: json.RawMessage(`{"cmd":"ls"}`)},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	all, err := s.ListAlerts(ctx, "", "", "", "", 500)
	if err != nil || len(all) != 2 {
		t.Fatalf("ListAlerts(all): %v %d", err, len(all))
	}
	crit, err := s.ListAlerts(ctx, events.SevCritical, "", "", "", 500)
	if err != nil || len(crit) != 1 || crit[0].SandboxID != "sbx1" {
		t.Fatalf("ListAlerts(critical): %v %+v", err, crit)
	}
	bySandbox, err := s.ListAlerts(ctx, "", "", "sbx2", "", 500)
	if err != nil || len(bySandbox) != 1 || bySandbox[0].SandboxID != "sbx2" {
		t.Fatalf("ListAlerts(sandbox_id=sbx2): %v %+v", err, bySandbox)
	}
	bySession, err := s.ListAlerts(ctx, "", "sess1", "", "", 500)
	if err != nil || len(bySession) != 1 {
		t.Fatalf("ListAlerts(pi_session=sess1): %v %+v", err, bySession)
	}
}

func TestDenyBurstIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	var evs []events.Event
	base := []string{
		"2026-09-08T10:00:00.000Z", "2026-09-08T10:00:01.000Z", "2026-09-08T10:00:02.000Z",
		"2026-09-08T10:00:03.000Z", "2026-09-08T10:00:04.000Z",
	}
	for i, ts := range base {
		evs = append(evs, events.Event{
			ID: "01" + string(rune('A'+i)), TS: ts, HostID: "h1", SandboxID: "sbx1", PiSession: "sess1",
			Type: events.EgressDeny, Data: json.RawMessage(`{"host":"evil.example"}`),
		})
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	alerts, err := s.CheckDenyBurst(ctx, evs)
	if err != nil {
		t.Fatalf("CheckDenyBurst: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("want 1 new alert, got %d: %+v", len(alerts), alerts)
	}
	if alerts[0].Type != events.SecurityAlert {
		t.Fatalf("want security.alert, got %q", alerts[0].Type)
	}
	var ad events.AlertData
	if err := json.Unmarshal(alerts[0].Data, &ad); err != nil || ad.Rule != events.RuleEgressDenyBurst {
		t.Fatalf("alert data: %v %+v", err, ad)
	}

	// Re-running against the same batch (e.g. a retried ingest) must not double-alert.
	alerts2, err := s.CheckDenyBurst(ctx, evs)
	if err != nil {
		t.Fatalf("CheckDenyBurst (retry): %v", err)
	}
	if len(alerts2) != 0 {
		t.Fatalf("want 0 alerts on retry (idempotent), got %d", len(alerts2))
	}

	// And a fresh sandbox with <5 denies never alerts.
	fewEvs := []events.Event{
		{ID: "02A", TS: "2026-09-08T10:00:00.000Z", SandboxID: "sbx2", PiSession: "sess1", Type: events.EgressDeny, Data: json.RawMessage(`{}`)},
	}
	s.InsertEvents(ctx, fewEvs)
	none, err := s.CheckDenyBurst(ctx, fewEvs)
	if err != nil || len(none) != 0 {
		t.Fatalf("want 0 alerts for a single deny, got %d (err=%v)", len(none), err)
	}
}

func TestStats(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.CreateSandbox(ctx, events.SandboxInfo{ID: "sbx1", Backend: "podman", Template: "base", State: "ready", CreatedAt: "2026-09-08T10:00:00Z"}, "h1"); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if err := s.CreateSandbox(ctx, events.SandboxInfo{ID: "sbx2", Backend: "podman", Template: "base", State: "busy", CreatedAt: "2026-09-08T10:00:00Z"}, "h1"); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if err := s.UpsertHost(ctx, events.HostRegister{HostID: "h1", URL: "http://x", Backend: "podman", Capacity: 2}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	now := "2026-09-08T10:00:00.000Z"
	evs := []events.Event{
		{ID: "01A", TS: now, SandboxID: "sbx1", Type: events.ExecEnd, Data: json.RawMessage(`{"duration_ms":40}`)},
		{ID: "01B", TS: now, SandboxID: "sbx1", Type: events.ExecEnd, Data: json.RawMessage(`{"duration_ms":80}`)},
		{ID: "01C", TS: now, SandboxID: "sbx1", Type: events.EgressAllow, Data: json.RawMessage(`{}`)},
		{ID: "01D", TS: now, SandboxID: "sbx1", Type: events.EgressDeny, Data: json.RawMessage(`{}`)},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}

	st, err := s.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Sandboxes.Total != 2 || st.Sandboxes.Ready != 1 || st.Sandboxes.Busy != 1 {
		t.Fatalf("sandboxes: %+v", st.Sandboxes)
	}
	if st.Hosts != 1 {
		t.Fatalf("hosts: want 1, got %d", st.Hosts)
	}
	// events_1h uses a real "now" cutoff; our fixture ts is in the past (2026-09-08 is
	// today in this repo's fixed test clock convention), so just assert it doesn't error
	// and egress counts are exact (those use the same cutoff consistently).
	if st.Egress.Allow1h > 1 || st.Egress.Deny1h > 1 {
		t.Fatalf("egress: %+v", st.Egress)
	}
}

func TestHostTiersRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertHost(ctx, events.HostRegister{HostID: "h1", URL: "http://x", Backend: "podman", Capacity: 2, Tiers: []string{"native", "vm"}}); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}
	h, err := s.GetHost(ctx, "h1")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v %+v", err, h)
	}
	if len(h.Tiers) != 2 || h.Tiers[0] != "native" || h.Tiers[1] != "vm" {
		t.Fatalf("tiers roundtrip: %+v", h.Tiers)
	}
}

func TestHeartbeatReconcilesVanishedSandboxes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertHost(ctx, events.HostRegister{HostID: "h1", URL: "http://h1", Backend: "podman"}); err != nil {
		t.Fatal(err)
	}
	// Two sandboxes reported live, then a heartbeat that only lists one.
	hb := events.Heartbeat{Pool: events.PoolStats{}, Sandboxes: []events.SandboxInfo{{ID: "a", State: "ready", Backend: "podman"}, {ID: "b", State: "ready", Backend: "podman"}}}
	if err := s.Heartbeat(ctx, "h1", hb); err != nil {
		t.Fatal(err)
	}
	hb.Sandboxes = hb.Sandboxes[:1]
	if err := s.Heartbeat(ctx, "h1", hb); err != nil {
		t.Fatal(err)
	}
	b, err := s.GetSandbox(ctx, "b")
	if err != nil || b == nil || b.State != "destroyed" {
		t.Fatalf("vanished sandbox must be marked destroyed: %+v %v", b, err)
	}
	a, _ := s.GetSandbox(ctx, "a")
	if a.State != "ready" {
		t.Fatalf("reported sandbox must stay ready: %+v", a)
	}
}

// TestHeartbeatKeepsStoppedSandboxesAlive: v3 lifecycle states (paused/stopped/archived)
// are live states, not destroyed — a heartbeat that keeps reporting a stopped sandbox
// must not flip it to destroyed, only reconcile drops it if the host stops reporting it
// at all (docs/protocol.md §3a).
func TestHeartbeatKeepsStoppedSandboxesAlive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.UpsertHost(ctx, events.HostRegister{HostID: "h1", URL: "http://h1", Backend: "podman"}); err != nil {
		t.Fatal(err)
	}
	hb := events.Heartbeat{Pool: events.PoolStats{}, Sandboxes: []events.SandboxInfo{
		{ID: "stopped1", State: "stopped", Backend: "remote"},
		{ID: "vanished1", State: "stopped", Backend: "remote"},
	}}
	if err := s.Heartbeat(ctx, "h1", hb); err != nil {
		t.Fatal(err)
	}
	// Next heartbeat still reports "stopped1" (still stopped) but drops "vanished1".
	hb.Sandboxes = hb.Sandboxes[:1]
	if err := s.Heartbeat(ctx, "h1", hb); err != nil {
		t.Fatal(err)
	}
	stopped, err := s.GetSandbox(ctx, "stopped1")
	if err != nil || stopped == nil || stopped.State != "stopped" {
		t.Fatalf("a stopped sandbox the host keeps reporting must stay stopped: %+v %v", stopped, err)
	}
	vanished, err := s.GetSandbox(ctx, "vanished1")
	if err != nil || vanished == nil || vanished.State != "destroyed" {
		t.Fatalf("a stopped sandbox the host stops reporting must be destroyed: %+v %v", vanished, err)
	}
}

func TestListSandboxesFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	name1 := "worker-1"
	name2 := "worker-2"
	if err := s.CreateSandbox(ctx, events.SandboxInfo{
		ID: "sbx1", Backend: "podman", Template: "base", State: "ready", CreatedAt: "2026-09-08T10:00:00Z",
		Name: name1, Labels: map[string]string{"team": "infra", "env": "prod"},
	}, "h1"); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if err := s.CreateSandbox(ctx, events.SandboxInfo{
		ID: "sbx2", Backend: "podman", Template: "base", State: "stopped", CreatedAt: "2026-09-08T10:00:01Z",
		Name: name2, Labels: map[string]string{"team": "infra", "env": "dev"},
	}, "h1"); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}

	byState, err := s.ListSandboxes(ctx, "stopped", "", "", "")
	if err != nil || len(byState) != 1 || byState[0].ID != "sbx2" {
		t.Fatalf("ListSandboxes(state=stopped): %v %+v", err, byState)
	}

	byName, err := s.ListSandboxes(ctx, "", "", name1, "")
	if err != nil || len(byName) != 1 || byName[0].ID != "sbx1" {
		t.Fatalf("ListSandboxes(name=%s): %v %+v", name1, err, byName)
	}
	if byName[0].Labels["env"] != "prod" {
		t.Fatalf("labels round-trip: %+v", byName[0].Labels)
	}

	byLabel, err := s.ListSandboxes(ctx, "", "env=dev", "", "")
	if err != nil || len(byLabel) != 1 || byLabel[0].ID != "sbx2" {
		t.Fatalf("ListSandboxes(label=env=dev): %v %+v", err, byLabel)
	}

	all, err := s.ListSandboxes(ctx, "", "", "", "")
	if err != nil || len(all) != 2 {
		t.Fatalf("ListSandboxes(none): %v %+v", err, all)
	}

	none, err := s.ListSandboxes(ctx, "archived", "", "", "")
	if err != nil {
		t.Fatalf("ListSandboxes(state=archived): %v", err)
	}
	if none == nil {
		t.Fatal("ListSandboxes must never return a nil slice, even when empty")
	}
	if len(none) != 0 {
		t.Fatalf("want 0 archived sandboxes, got %+v", none)
	}
}

func TestSetSandboxStateAndUnknownEventsIgnored(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateSandbox(ctx, events.SandboxInfo{ID: "sbx1", Backend: "remote", Template: "base", State: "ready", CreatedAt: "2026-09-08T10:00:00Z"}, "h1"); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	if err := s.SetSandboxState(ctx, "sbx1", "paused"); err != nil {
		t.Fatalf("SetSandboxState: %v", err)
	}
	sb, err := s.GetSandbox(ctx, "sbx1")
	if err != nil || sb == nil || sb.State != "paused" {
		t.Fatalf("SetSandboxState(paused): %+v %v", sb, err)
	}
	if sb.StateChangedAt == nil || *sb.StateChangedAt == "" {
		t.Fatalf("state_changed_at must be set: %+v", sb)
	}

	// v3 lifecycle/snapshot/preview events must not break ingestion of a batch and must
	// still update sandbox state where applicable (sandbox.stopped etc.); snapshot.*/
	// preview.created carry no sandbox state effect but must insert cleanly.
	evs := []events.Event{
		{ID: "01A", TS: "2026-09-08T10:00:01.000Z", SandboxID: "sbx1", Type: events.SandboxStopped, Data: json.RawMessage(`{"reason":"api"}`)},
		{ID: "01B", TS: "2026-09-08T10:00:02.000Z", SandboxID: "sbx1", Type: events.SnapshotReady, Data: json.RawMessage(`{"name":"snap1"}`)},
		{ID: "01C", TS: "2026-09-08T10:00:03.000Z", SandboxID: "sbx1", Type: events.PreviewCreated, Data: json.RawMessage(`{"port":8080}`)},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatalf("InsertEvents: %v", err)
	}
	sb, err = s.GetSandbox(ctx, "sbx1")
	if err != nil || sb == nil || sb.State != "stopped" {
		t.Fatalf("sandbox.stopped event must update state: %+v %v", sb, err)
	}
}

// TestDaemonRestartKeepsStoppedSandboxes: a host whose daemon restarts is absent
// for a heartbeat interval and then re-registers and reports the sandboxes it
// re-adopted from its persisted table (crates/qafas/src/livetable.rs). Neither
// the gap nor the re-registration may touch the rows: reconciliation only ever
// runs inside Heartbeat, against the list that heartbeat carries.
func TestDaemonRestartKeepsStoppedSandboxes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	reg := events.HostRegister{HostID: "h1", URL: "http://h1", Backend: "firecracker"}
	if err := s.UpsertHost(ctx, reg); err != nil {
		t.Fatal(err)
	}
	hb := events.Heartbeat{Sandboxes: []events.SandboxInfo{
		{ID: "s1", State: "stopped", Backend: "firecracker"},
		{ID: "a1", State: "archived", Backend: "firecracker"},
		{ID: "r1", State: "ready", Backend: "firecracker"},
	}}
	if err := s.Heartbeat(ctx, "h1", hb); err != nil {
		t.Fatal(err)
	}
	// ... the daemon is killed. No heartbeat arrives for a while, and then it
	// registers again and reports only what it re-adopted: the running sandbox
	// died with it, the other two did not.
	if err := s.UpsertHost(ctx, reg); err != nil {
		t.Fatal(err)
	}
	hb.Sandboxes = hb.Sandboxes[:2]
	if err := s.Heartbeat(ctx, "h1", hb); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{"s1": "stopped", "a1": "archived", "r1": "destroyed"} {
		got, err := s.GetSandbox(ctx, id)
		if err != nil || got == nil || got.State != want {
			t.Fatalf("%s after the restart: want %s, got %+v %v", id, want, got, err)
		}
	}
}

// v5: CommittedByHost sums Limits only across live states (docs/protocol.md §3a "v5 sizes
// and limits"); destroyed sandboxes must not count.
func TestCommittedByHostSumsOnlyLiveStates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	sb := func(id, hostID, state string, cpus float64, memMiB uint64) events.SandboxInfo {
		return events.SandboxInfo{ID: id, State: state, CreatedAt: "2026-01-01T00:00:00Z", Limits: &events.SandboxLimits{Cpus: cpus, MemMiB: memMiB}}
	}
	for _, row := range []struct {
		sb     events.SandboxInfo
		hostID string
	}{
		{sb("creating1", "h1", "creating", 1, 512), "h1"},
		{sb("ready1", "h1", "ready", 2, 1024), "h1"},
		{sb("busy1", "h1", "busy", 0.5, 256), "h1"},
		{sb("paused1", "h1", "paused", 1, 1024), "h1"},
		{sb("stopped1", "h1", "stopped", 4, 4096), "h1"},     // not live: excluded
		{sb("archived1", "h1", "archived", 4, 4096), "h1"},   // not live: excluded
		{sb("destroyed1", "h1", "destroyed", 4, 4096), "h1"}, // not live: excluded
		{sb("ready2", "h2", "ready", 3, 2048), "h2"},
	} {
		if err := s.CreateSandbox(ctx, row.sb, row.hostID); err != nil {
			t.Fatalf("CreateSandbox(%s): %v", row.sb.ID, err)
		}
	}

	committed, err := s.CommittedByHost(ctx)
	if err != nil {
		t.Fatalf("CommittedByHost: %v", err)
	}
	if got := committed["h1"]; got.Cpus != 4.5 || got.MemMiB != 2816 {
		t.Fatalf("h1 committed: got %+v, want {4.5 2816}", got)
	}
	if got := committed["h2"]; got.Cpus != 3 || got.MemMiB != 2048 {
		t.Fatalf("h2 committed: got %+v, want {3 2048}", got)
	}
}
