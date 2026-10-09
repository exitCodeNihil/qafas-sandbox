// v2.go: sessions, alerts, stats, search, process trees, retention, and the deny-burst
// detector — everything phase 2 (phase 2) adds on top of the phase-1
// events/hosts/sandboxes tables. No new tables: sessions and alerts are both queries over
// `events` using the indexes already created in store.go.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

// ---- sessions

type AlertCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type SessionSummary struct {
	PiSession  string      `json:"pi_session"`
	FirstTS    string      `json:"first_ts"`
	LastTS     string      `json:"last_ts"`
	SandboxIDs []string    `json:"sandbox_ids"`
	Hosts      []string    `json:"hosts"`
	Events     int         `json:"events"`
	Execs      int         `json:"execs"`
	Alerts     AlertCounts `json:"alerts"`
	TopAlert   string      `json:"top_alert,omitempty"`
	// v3: from the session's first (most recently created) sandbox, docs/protocol.md §4b.
	ApiKeyID   string `json:"api_key_id,omitempty"`
	ApiKeyName string `json:"api_key_name,omitempty"`
}

type SessionDetail struct {
	SessionSummary
	Sandboxes []events.SandboxInfo `json:"sandboxes"`
}

// ListSessions aggregates events(pi_session,ts) into one row per session, newest last-seen
// first. q, when set, filters by substring match on the session id. sandboxID, when set,
// keeps only sessions that touch that sandbox anywhere in their history (the row itself
// still aggregates every sandbox of the session, not just this one).
func (s *Store) ListSessions(ctx context.Context, limit int, q, sandboxID string) ([]SessionSummary, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT pi_session, MIN(ts), MAX(ts), COUNT(*), SUM(type='exec.start'),
		GROUP_CONCAT(DISTINCT sandbox_id), GROUP_CONCAT(DISTINCT host_id)
		FROM events WHERE pi_session != ''`
	args := []any{}
	if q != "" {
		query += ` AND pi_session LIKE ?`
		args = append(args, "%"+q+"%")
	}
	if sandboxID != "" {
		query += ` AND pi_session IN (SELECT DISTINCT pi_session FROM events WHERE sandbox_id = ?)`
		args = append(args, sandboxID)
	}
	query += ` GROUP BY pi_session ORDER BY MAX(ts) DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	var out []SessionSummary
	var ids []string
	for rows.Next() {
		var sess SessionSummary
		var sandboxCSV, hostCSV sql.NullString
		if err := rows.Scan(&sess.PiSession, &sess.FirstTS, &sess.LastTS, &sess.Events, &sess.Execs, &sandboxCSV, &hostCSV); err != nil {
			rows.Close()
			return nil, err
		}
		sess.SandboxIDs = splitCSV(sandboxCSV.String)
		sess.Hosts = splitCSV(hostCSV.String)
		out = append(out, sess)
		ids = append(ids, sess.PiSession)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	agg, err := s.alertCountsForSessions(ctx, ids)
	if err != nil {
		return nil, err
	}
	keys, err := s.apiKeyForSessions(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		a := agg[out[i].PiSession]
		out[i].Alerts = a.counts
		out[i].TopAlert = a.topRule
		if k, ok := keys[out[i].PiSession]; ok {
			out[i].ApiKeyID, out[i].ApiKeyName = k[0], k[1]
		}
	}
	return out, nil
}

// apiKeyForSessions batches, for each of the given sessions, the api_key_id/name of its
// most-recently-created sandbox ("the session's first sandbox", docs/protocol.md §4b) —
// same DESC-by-created_at convention sandboxesForSession/GetSession already use, so
// SessionDetail.Sandboxes[0] and this function agree on what "first" means.
func (s *Store) apiKeyForSessions(ctx context.Context, sessions []string) (map[string][2]string, error) {
	out := map[string][2]string{}
	if len(sessions) == 0 {
		return out, nil
	}
	args := make([]any, len(sessions))
	for i, sid := range sessions {
		args[i] = sid
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT sandboxes.pi_session, sandboxes.api_key_id, COALESCE(ak.name,'')
		FROM sandboxes LEFT JOIN api_keys ak ON sandboxes.api_key_id = ak.id
		WHERE sandboxes.pi_session IN (`+placeholders(len(sessions))+`)
		ORDER BY sandboxes.pi_session, sandboxes.created_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sid, keyID, keyName string
		if err := rows.Scan(&sid, &keyID, &keyName); err != nil {
			return nil, err
		}
		if _, ok := out[sid]; !ok { // first row per session (DESC order) wins
			out[sid] = [2]string{keyID, keyName}
		}
	}
	return out, rows.Err()
}

// GetSession returns the aggregated row for one session plus its sandboxes, or nil if the
// session has no events.
func (s *Store) GetSession(ctx context.Context, id string) (*SessionDetail, error) {
	var firstTS, lastTS, sandboxCSV, hostCSV sql.NullString
	var evCount int
	var execs sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MIN(ts),MAX(ts),COUNT(*),SUM(type='exec.start'),
		GROUP_CONCAT(DISTINCT sandbox_id), GROUP_CONCAT(DISTINCT host_id)
		FROM events WHERE pi_session=?`, id).Scan(&firstTS, &lastTS, &evCount, &execs, &sandboxCSV, &hostCSV)
	if err != nil {
		return nil, err
	}
	if !firstTS.Valid {
		return nil, nil
	}
	sess := SessionSummary{
		PiSession: id, FirstTS: firstTS.String, LastTS: lastTS.String,
		Events: evCount, Execs: int(execs.Int64),
		SandboxIDs: splitCSV(sandboxCSV.String), Hosts: splitCSV(hostCSV.String),
	}
	agg, err := s.alertCountsForSessions(ctx, []string{id})
	if err != nil {
		return nil, err
	}
	a := agg[id]
	sess.Alerts = a.counts
	sess.TopAlert = a.topRule

	sbxs, err := s.sandboxesForSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if sbxs == nil {
		sbxs = []events.SandboxInfo{} // a sandbox created straight on qafas is unknown here; still not null
	}
	if len(sbxs) > 0 { // sandboxesForSession orders DESC by created_at: [0] is "the first sandbox"
		sess.ApiKeyID, sess.ApiKeyName = sbxs[0].ApiKeyID, sbxs[0].ApiKeyName
	}
	return &SessionDetail{SessionSummary: sess, Sandboxes: sbxs}, nil
}

func (s *Store) sandboxesForSession(ctx context.Context, piSession string) ([]events.SandboxInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sandboxSelectCols+` `+sandboxFrom+` WHERE sandboxes.pi_session=? ORDER BY sandboxes.created_at DESC`, piSession)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSandboxes(rows)
}

// sessionEventsPageSize bounds each round trip ListAllSessionEvents makes.
const sessionEventsPageSize = 5000

// ListAllSessionEvents pages through ListSessionEvents (sessionEventsPageSize per round
// trip) and returns the full session history, ascending by id — for callers that need every
// event in memory (the trace builder, the OTLP pusher) instead of one unbounded query.
func (s *Store) ListAllSessionEvents(ctx context.Context, piSession string) ([]events.Event, error) {
	var out []events.Event
	after := ""
	for {
		page, err := s.ListSessionEvents(ctx, piSession, after, nil, sessionEventsPageSize)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < sessionEventsPageSize {
			return out, nil
		}
		after = page[len(page)-1].ID
	}
}

// ListSessionEvents returns events for every sandbox of a session, ascending by id, after
// cursor `after` (exclusive), optionally restricted to `types`.
func (s *Store) ListSessionEvents(ctx context.Context, piSession, after string, types []string, limit int) ([]events.Event, error) {
	if limit <= 0 {
		limit = 500
	}
	query := `SELECT id,ts,host_id,sandbox_id,pi_session,tool_call_id,type,data FROM events WHERE pi_session=? AND id>?`
	args := []any{piSession, after}
	if len(types) > 0 {
		query += ` AND type IN (` + placeholders(len(types)) + `)`
		for _, t := range types {
			args = append(args, t)
		}
	}
	query += ` ORDER BY id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// ListEvents is the global list (protocol §4 v2 `GET /api/events`): newest first,
// optionally narrowed by type, session or sandbox.
func (s *Store) ListEvents(ctx context.Context, types []string, piSession, sandboxID, after string, limit int) ([]events.Event, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	query := `SELECT id,ts,host_id,sandbox_id,pi_session,tool_call_id,type,data FROM events WHERE id>?`
	args := []any{after}
	if len(types) > 0 {
		query += ` AND type IN (` + placeholders(len(types)) + `)`
		for _, t := range types {
			args = append(args, t)
		}
	}
	if piSession != "" {
		query += ` AND pi_session=?`
		args = append(args, piSession)
	}
	if sandboxID != "" {
		query += ` AND sandbox_id=?`
		args = append(args, sandboxID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// MarkDestroyed records a destroy requested through the control plane, without waiting
// for the host's sandbox.destroyed event to arrive.
func (s *Store) MarkDestroyed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sandboxes SET state='destroyed', destroyed_at=COALESCE(destroyed_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id=?`, id)
	return err
}

// ---- alerts

func (s *Store) ListAlerts(ctx context.Context, severity, piSession, sandboxID, since string, limit int) ([]events.Event, error) {
	if limit <= 0 {
		limit = 500
	}
	query := `SELECT id,ts,host_id,sandbox_id,pi_session,tool_call_id,type,data FROM events WHERE type='security.alert'`
	args := []any{}
	if severity != "" {
		query += ` AND json_extract(data,'$.severity')=?`
		args = append(args, severity)
	}
	if piSession != "" {
		query += ` AND pi_session=?`
		args = append(args, piSession)
	}
	if sandboxID != "" {
		query += ` AND sandbox_id=?`
		args = append(args, sandboxID)
	}
	if since != "" {
		query += ` AND ts>=?`
		args = append(args, since)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

type alertAgg struct {
	counts  AlertCounts
	topRule string
}

// severityRankSQL is the severity->rank CASE expression shared by the two
// alertCountsForSessions queries below (json_extract(data,'$.severity') as its operand).
const severityRankSQL = `CASE %s WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

// alertCountsForSessions batches two SQL aggregations for all requested sessions: per-
// severity counts (one SUM per severity, GROUP BY pi_session) and each session's top
// (highest-severity) rule, via a window function ranking rows within each session and
// keeping the first at max rank (ties broken by id, i.e. earliest).
func (s *Store) alertCountsForSessions(ctx context.Context, sessions []string) (map[string]alertAgg, error) {
	out := map[string]alertAgg{}
	if len(sessions) == 0 {
		return out, nil
	}
	args := make([]any, len(sessions))
	for i, sid := range sessions {
		args[i] = sid
	}
	in := placeholders(len(sessions))

	countRows, err := s.db.QueryContext(ctx, `
		SELECT pi_session,
			SUM(json_extract(data,'$.severity')='critical'),
			SUM(json_extract(data,'$.severity')='high'),
			SUM(json_extract(data,'$.severity')='medium'),
			SUM(json_extract(data,'$.severity')='low')
		FROM events WHERE type='security.alert' AND pi_session IN (`+in+`)
		GROUP BY pi_session`, args...)
	if err != nil {
		return nil, err
	}
	defer countRows.Close()
	for countRows.Next() {
		var sid string
		var agg alertAgg
		if err := countRows.Scan(&sid, &agg.counts.Critical, &agg.counts.High, &agg.counts.Medium, &agg.counts.Low); err != nil {
			return nil, err
		}
		out[sid] = agg
	}
	if err := countRows.Err(); err != nil {
		return nil, err
	}

	rank := fmt.Sprintf(severityRankSQL, "json_extract(data,'$.severity')")
	topRows, err := s.db.QueryContext(ctx, `
		WITH ranked AS (
			SELECT pi_session, json_extract(data,'$.rule') AS rule, `+rank+` AS rnk,
				ROW_NUMBER() OVER (PARTITION BY pi_session ORDER BY `+rank+` DESC, id ASC) AS rn
			FROM events WHERE type='security.alert' AND pi_session IN (`+in+`)
		)
		SELECT pi_session, rule FROM ranked WHERE rn = 1 AND rnk > 0`, args...)
	if err != nil {
		return nil, err
	}
	defer topRows.Close()
	for topRows.Next() {
		var sid, rule string
		if err := topRows.Scan(&sid, &rule); err != nil {
			return nil, err
		}
		agg := out[sid]
		agg.topRule = rule
		out[sid] = agg
	}
	return out, topRows.Err()
}

func bumpSeverity(c *AlertCounts, sev string) {
	switch sev {
	case events.SevCritical:
		c.Critical++
	case events.SevHigh:
		c.High++
	case events.SevMedium:
		c.Medium++
	case events.SevLow:
		c.Low++
	}
}

// CheckDenyBurst inspects a just-ingested batch for sandboxes with >=5 egress.deny in the
// last 10s and, if the daemon didn't already report `security.alert{rule:egress.deny_burst}`
// in that same window, inserts one and returns it so the caller can hub.Publish it.
// Idempotent: re-ingesting the same window (e.g. a retried batch) never double-alerts,
// because the existence check runs against the same 10s window every time.
func (s *Store) CheckDenyBurst(ctx context.Context, evs []events.Event) ([]events.Event, error) {
	sandboxSet := map[string]bool{}
	for _, e := range evs {
		if e.Type == events.EgressDeny && e.SandboxID != "" {
			sandboxSet[e.SandboxID] = true
		}
	}
	var alerts []events.Event
	for sandboxID := range sandboxSet {
		var latestTS sql.NullString
		if err := s.db.QueryRowContext(ctx, `SELECT MAX(ts) FROM events WHERE sandbox_id=? AND type='egress.deny'`, sandboxID).Scan(&latestTS); err != nil {
			return nil, err
		}
		if !latestTS.Valid {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, latestTS.String)
		if err != nil {
			continue
		}
		windowStart := t.Add(-10 * time.Second).UTC().Format("2006-01-02T15:04:05.000Z")

		var count int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE sandbox_id=? AND type='egress.deny' AND ts>=?`, sandboxID, windowStart).Scan(&count); err != nil {
			return nil, err
		}
		if count < 5 {
			continue
		}
		var existing int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE sandbox_id=? AND type='security.alert' AND ts>=? AND json_extract(data,'$.rule')=?`,
			sandboxID, windowStart, events.RuleEgressDenyBurst).Scan(&existing); err != nil {
			return nil, err
		}
		if existing > 0 {
			continue // the daemon (or a previous ingest of this same window) already alerted
		}

		var piSession, hostID string
		_ = s.db.QueryRowContext(ctx, `SELECT pi_session, host_id FROM events WHERE sandbox_id=? AND type='egress.deny' ORDER BY ts DESC LIMIT 1`, sandboxID).Scan(&piSession, &hostID)

		data, _ := json.Marshal(events.AlertData{Severity: events.SevMedium, Rule: events.RuleEgressDenyBurst, Msg: fmt.Sprintf("%d egress.deny in 10s", count)})
		alert := events.Event{
			// ts = the triggering deny's own ts (not time.Now()): keeps the alert inside the
			// same [windowStart,latestTS] window this function itself checks on the next
			// ingest, so idempotency holds regardless of any gap between event time and
			// wall-clock ingest time. NewULID's own timestamp (real "now") only affects sort
			// order among events, not this window check.
			ID: events.NewULID(), TS: latestTS.String,
			HostID: hostID, SandboxID: sandboxID, PiSession: piSession, Type: events.SecurityAlert, Data: data,
		}
		res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO events(id,ts,host_id,sandbox_id,pi_session,tool_call_id,type,data) VALUES(?,?,?,?,?,?,?,?)`,
			alert.ID, alert.TS, alert.HostID, alert.SandboxID, alert.PiSession, "", alert.Type, string(alert.Data))
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n > 0 { // keep events_fts in sync (store.go's InsertEvents does the same)
			if _, err := s.db.ExecContext(ctx, `INSERT INTO events_fts(id,ts,data) VALUES(?,?,?)`, alert.ID, alert.TS, string(alert.Data)); err != nil {
				return nil, err
			}
		}
		alerts = append(alerts, alert)
	}
	return alerts, nil
}

// ---- stats

type Stats struct {
	Sandboxes struct {
		Ready int `json:"ready"`
		Busy  int `json:"busy"`
		Total int `json:"total"`
	} `json:"sandboxes"`
	Hosts     int         `json:"hosts"`
	Events1h  int         `json:"events_1h"`
	Alerts24h AlertCounts `json:"alerts_24h"`
	ExecP50Ms float64     `json:"exec_p50_ms"`
	ExecP95Ms float64     `json:"exec_p95_ms"`
	Egress    struct {
		Allow1h int `json:"allow_1h"`
		Deny1h  int `json:"deny_1h"`
	} `json:"egress"`
}

func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{}
	var ready, busy sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT SUM(state='ready'), SUM(state='busy'), COUNT(*) FROM sandboxes WHERE state != 'destroyed'`).
		Scan(&ready, &busy, &st.Sandboxes.Total); err != nil {
		return nil, err
	}
	st.Sandboxes.Ready = int(ready.Int64)
	st.Sandboxes.Busy = int(busy.Int64)

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts`).Scan(&st.Hosts); err != nil {
		return nil, err
	}

	cutoff1h := time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05.000Z")
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE ts>=?`, cutoff1h).Scan(&st.Events1h); err != nil {
		return nil, err
	}

	cutoff24h := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z")
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM events WHERE type='security.alert' AND ts>=?`, cutoff24h)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return nil, err
		}
		var ad events.AlertData
		if json.Unmarshal([]byte(data), &ad) == nil {
			bumpSeverity(&st.Alerts24h, ad.Severity)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	durs, err := s.recentExecDurations(ctx, 1000)
	if err != nil {
		return nil, err
	}
	st.ExecP50Ms = percentile(durs, 50)
	st.ExecP95Ms = percentile(durs, 95)

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='egress.allow' AND ts>=?`, cutoff1h).Scan(&st.Egress.Allow1h); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='egress.deny' AND ts>=?`, cutoff1h).Scan(&st.Egress.Deny1h); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) recentExecDurations(ctx context.Context, n int) ([]float64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT data FROM events WHERE type='exec.end' ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []float64
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var payload struct {
			DurationMs float64 `json:"duration_ms"`
		}
		if json.Unmarshal([]byte(data), &payload) == nil {
			out = append(out, payload.DurationMs)
		}
	}
	return out, rows.Err()
}

func percentile(vals []float64, p float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	idx := int(p / 100 * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// ---- search

// Search matches events via the events_fts shadow table: each whitespace-separated token in
// q becomes a quoted prefix match (implicit AND between tokens — covers cmd/path/host/argv/
// msg without per-type field extraction), ranked by FTS5's bm25 relevance. An empty/blank q
// is a browse view: the most recent events, newest first.
func (s *Store) Search(ctx context.Context, q string, limit int) ([]events.Event, error) {
	if limit <= 0 {
		limit = 200
	}
	if strings.TrimSpace(q) == "" {
		rows, err := s.db.QueryContext(ctx, `SELECT id,ts,host_id,sandbox_id,pi_session,tool_call_id,type,data FROM events ORDER BY id DESC LIMIT ?`, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanEvents(rows)
	}
	// bm25() takes the FTS5 table's real name, not the join alias (modernc sqlite errors
	// "no such column" otherwise); f.data MATCH still works fine aliased.
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id,e.ts,e.host_id,e.sandbox_id,e.pi_session,e.tool_call_id,e.type,e.data
		FROM events_fts f JOIN events e ON e.id = f.id
		WHERE f.data MATCH ? ORDER BY bm25(events_fts) LIMIT ?`, ftsPrefixQuery(q), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// ftsPrefixQuery turns a raw search string into an FTS5 MATCH query: each token, quoted (so
// punctuation in a path/host/cmd doesn't collide with FTS5 query syntax) and suffixed `*`
// for a prefix match.
func ftsPrefixQuery(q string) string {
	fields := strings.Fields(q)
	parts := make([]string, len(fields))
	for i, f := range fields {
		parts[i] = `"` + strings.ReplaceAll(f, `"`, `""`) + `"*`
	}
	return strings.Join(parts, " ")
}

// ---- process trees

type ProcessNode struct {
	PID        int            `json:"pid"`
	PPID       int            `json:"ppid"`
	Argv       []string       `json:"argv"`
	StartTS    string         `json:"start_ts"`
	EndTS      *string        `json:"end_ts,omitempty"`
	Exit       *int           `json:"exit,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	Children   []*ProcessNode `json:"children"` // never null: the dashboard indexes it
}

// ListProcessesForSession builds the process forest for a session from process.start/exit
// events across all its sandboxes (roots = processes whose parent pid has no node of its
// own within the same sandbox — usually the exec's own child).
func (s *Store) ListProcessesForSession(ctx context.Context, piSession string) ([]*ProcessNode, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sandbox_id, tool_call_id, type, data, ts FROM events
		WHERE pi_session=? AND type IN ('process.start','process.exit') ORDER BY ts ASC`, piSession)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type key struct{ sandbox, pid string }
	nodes := map[key]*ProcessNode{}
	ppidOf := map[key]int{}
	var order []key

	for rows.Next() {
		var sandboxID, toolCallID, typ, data, ts string
		if err := rows.Scan(&sandboxID, &toolCallID, &typ, &data, &ts); err != nil {
			return nil, err
		}
		if typ == "process.start" {
			var p struct {
				PID  int      `json:"pid"`
				PPID int      `json:"ppid"`
				Argv []string `json:"argv"`
			}
			if json.Unmarshal([]byte(data), &p) != nil {
				continue
			}
			k := key{sandboxID, strconv.Itoa(p.PID)}
			nodes[k] = &ProcessNode{PID: p.PID, PPID: p.PPID, Argv: p.Argv, StartTS: ts, ToolCallID: toolCallID, Children: []*ProcessNode{}}
			ppidOf[k] = p.PPID
			order = append(order, k)
		} else {
			var p struct {
				PID  int `json:"pid"`
				Exit int `json:"exit"`
			}
			if json.Unmarshal([]byte(data), &p) != nil {
				continue
			}
			k := key{sandboxID, strconv.Itoa(p.PID)}
			if n, ok := nodes[k]; ok {
				endTS := ts
				n.EndTS = &endTS
				exit := p.Exit
				n.Exit = &exit
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	roots := []*ProcessNode{} // JSON [] when every process was too short for the sweep
	for _, k := range order {
		n := nodes[k]
		pk := key{k.sandbox, strconv.Itoa(ppidOf[k])}
		if parent, ok := nodes[pk]; ok && pk != k {
			parent.Children = append(parent.Children, n)
		} else {
			roots = append(roots, n)
		}
	}
	return roots, nil
}

// ---- retention

// SweepRetention deletes events older than `days`. design: events only; destroyed
// sandbox/host rows aren't swept, they're cheap at POC scale.
func (s *Store) SweepRetention(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02T15:04:05.000Z")
	if _, err := s.db.ExecContext(ctx, `DELETE FROM events_fts WHERE ts < ?`, cutoff); err != nil {
		return 0, err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---- helpers

func splitCSV(s string) []string {
	if s == "" {
		return []string{} // never null: the dashboard joins it
	}
	return strings.Split(s, ",")
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
