// Package store is the sqlite-backed persistence layer (modernc.org/sqlite, pure Go,
// so CGO_ENABLED=0 keeps working). The schema is applied as forward-only
// embedded migrations.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

type Store struct {
	db   *sql.DB
	path string
}

// migrations is forward-only: append, never edit past entries.
var migrations = []string{
	`CREATE TABLE IF NOT EXISTS hosts(
		id TEXT PRIMARY KEY, url TEXT, backend TEXT, capacity INT, pool TEXT, last_seen TEXT
	);`,
	`CREATE TABLE IF NOT EXISTS sandboxes(
		id TEXT PRIMARY KEY, host_id TEXT, template TEXT, backend TEXT, workspace TEXT,
		pi_session TEXT, state TEXT, created_at TEXT, ready_at TEXT, destroyed_at TEXT
	);`,
	`CREATE TABLE IF NOT EXISTS events(
		id TEXT PRIMARY KEY, ts TEXT, host_id TEXT, sandbox_id TEXT, pi_session TEXT,
		tool_call_id TEXT, type TEXT, data TEXT
	);`,
	`CREATE INDEX IF NOT EXISTS events_sandbox_ts ON events(sandbox_id,ts);`,
	`CREATE INDEX IF NOT EXISTS events_session_ts ON events(pi_session,ts);`,
	`CREATE INDEX IF NOT EXISTS events_type_ts ON events(type,ts);`,
	// v3: API keys (docs/protocol.md §4b).
	`CREATE TABLE IF NOT EXISTS api_keys(
		id TEXT PRIMARY KEY, name TEXT, prefix TEXT, secret_sha256 TEXT,
		scopes TEXT NOT NULL DEFAULT '[]', limits TEXT NOT NULL DEFAULT '{}', labels TEXT NOT NULL DEFAULT '{}',
		created_at TEXT, last_used_at TEXT, revoked_at TEXT
	);`,
	`CREATE UNIQUE INDEX IF NOT EXISTS api_keys_prefix ON api_keys(prefix);`,
	// v4: observability settings (docs/protocol.md §4 v4 GET/PUT /api/settings/observability).
	`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);`,
	// v2 search: an FTS5 shadow table over events.data (id/ts kept but unindexed, for the
	// join back to `events` and for SweepRetention's cutoff delete). Kept in sync by
	// InsertEvents/SweepRetention rather than SQL triggers — events are insert-only besides
	// that one bulk delete, so there's no update path to trigger on.
	`CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(id UNINDEXED, ts UNINDEXED, data);`,
}

// Open opens (creating if needed) the sqlite database at path, sets WAL + busy_timeout,
// and applies migrations.
func Open(path string) (*Store, error) {
	// _pragma params applied on every new connection (modernc driver requirement for WAL).
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // design: sqlite + WAL tolerates more, but one writer keeps this simple; raise if throughput demands it.
	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// DBPath returns the sqlite file path this store was opened with, for GET /metrics'
// sbxcp_db_bytes (docs/protocol.md §4 v4).
func (s *Store) DBPath() string { return s.path }

func (s *Store) migrate() error {
	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// v2 columns: ALTER TABLE ADD COLUMN isn't idempotent like CREATE TABLE IF NOT EXISTS,
	// so these are guarded rather than added to the `migrations` slice above.
	if err := addColumnIfMissing(s.db, "hosts", "tiers", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := addColumnIfMissing(s.db, "sandboxes", "isolation", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := addColumnIfMissing(s.db, "hosts", "tls_fingerprint", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if err := addColumnIfMissing(s.db, "hosts", "policy", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// v4c: what the host can do, from qafas doctor (docs/protocol.md §3a).
	if err := addColumnIfMissing(s.db, "hosts", "caps", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// v3 columns: lifecycle (docs/protocol.md §3a).
	for _, c := range []struct{ col, decl string }{
		{"name", "TEXT NOT NULL DEFAULT ''"},
		{"labels", "TEXT NOT NULL DEFAULT '{}'"},
		{"state_changed_at", "TEXT"},
		{"auto_stop_secs", "INTEGER"},
		{"auto_archive_secs", "INTEGER"},
		{"auto_delete_secs", "INTEGER"},
		{"max_age_secs", "INTEGER"},
		// v3: which API key created it (docs/protocol.md §4b). qafas knows nothing
		// about keys, so this is set by the control plane on CreateSandbox only.
		{"api_key_id", "TEXT NOT NULL DEFAULT ''"},
		// v4: live counters copied from the last heartbeat (≤10 s stale) so the
		// dashboard can say "sleeps in …" without dialling the host.
		{"idle_secs", "INTEGER NOT NULL DEFAULT 0"},
		{"running_secs", "INTEGER NOT NULL DEFAULT 0"},
		// v5: sizes and limits (docs/protocol.md §3a "v5 sizes and limits").
		{"size", "TEXT NOT NULL DEFAULT ''"},
		{"limits", "TEXT NOT NULL DEFAULT '{}'"},
		{"usage", "TEXT NOT NULL DEFAULT '{}'"},
		{"enforcement", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := addColumnIfMissing(s.db, "sandboxes", c.col, c.decl); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	if err := backfillEventsFTS(s.db); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// backfillEventsFTS runs once, the first time an existing (pre-FTS5) database opens against
// this migration: events_fts starts empty even though `events` already has rows, so copy
// them across. A no-op on a fresh database (both start at 0) and on every later boot (the
// table is already populated by InsertEvents from then on).
func backfillEventsFTS(db *sql.DB) error {
	var ftsCount, evCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events_fts`).Scan(&ftsCount); err != nil {
		return err
	}
	if ftsCount > 0 {
		return nil
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&evCount); err != nil {
		return err
	}
	if evCount == 0 {
		return nil
	}
	_, err := db.Exec(`INSERT INTO events_fts(id, ts, data) SELECT id, ts, data FROM events`)
	return err
}

func addColumnIfMissing(db *sql.DB, table, column, decl string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl))
	return err
}

// ---- hosts

func (s *Store) UpsertHost(ctx context.Context, h events.HostRegister) error {
	tiersJSON, err := json.Marshal(h.Tiers)
	if err != nil {
		return err
	}
	policy := "{}"
	if len(h.Policy) > 0 {
		policy = string(h.Policy)
	}
	capsJSON, err := json.Marshal(h.Caps)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO hosts(id,url,backend,capacity,pool,last_seen,tiers,tls_fingerprint,policy,caps) VALUES(?,?,?,?,'{}',strftime('%Y-%m-%dT%H:%M:%fZ','now'),?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET url=excluded.url, backend=excluded.backend, capacity=excluded.capacity,
			last_seen=strftime('%Y-%m-%dT%H:%M:%fZ','now'), tiers=excluded.tiers, tls_fingerprint=excluded.tls_fingerprint, policy=excluded.policy, caps=excluded.caps`,
		h.HostID, h.URL, h.Backend, h.Capacity, string(tiersJSON), h.TLSFingerprint, policy, string(capsJSON))
	return err
}

func (s *Store) Heartbeat(ctx context.Context, hostID string, hb events.Heartbeat) error {
	poolJSON, err := json.Marshal(hb.Pool)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `UPDATE hosts SET pool=?, last_seen=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`, string(poolJSON), hostID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("unknown host %q", hostID)
	}
	for _, sb := range hb.Sandboxes {
		if err := upsertSandboxTx(ctx, tx, hostID, sb); err != nil {
			return err
		}
	}
	// The heartbeat is the host's full list: anything we still consider live on
	// this host but the host no longer reports was destroyed while we could not
	// hear it (host restart, dropped event batch). Reconcile. v3: paused/stopped/
	// archived are live states too (the sandbox still exists, just not running) —
	// they only flip to destroyed when the host stops reporting them at all.
	live := make([]any, 0, len(hb.Sandboxes)+1)
	q := `UPDATE sandboxes SET state='destroyed', destroyed_at=COALESCE(destroyed_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')), state_changed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
	      WHERE host_id=? AND state IN ('creating','ready','busy','paused','stopped','archived')`
	live = append(live, hostID)
	if len(hb.Sandboxes) > 0 {
		q += ` AND id NOT IN (` + placeholders(len(hb.Sandboxes)) + `)`
		for _, sb := range hb.Sandboxes {
			live = append(live, sb.ID)
		}
	}
	if _, err := tx.ExecContext(ctx, q, live...); err != nil {
		return err
	}
	return tx.Commit()
}

// sandboxInsertCols/Placeholders are shared by CreateSandbox and the heartbeat upsert:
// same 18 bound columns (destroyed_at is always NULL on insert, set later by
// UpdateSandboxState/MarkDestroyed).
const (
	sandboxInsertCols = `id,host_id,template,backend,workspace,pi_session,state,created_at,ready_at,destroyed_at,isolation,
		name,labels,state_changed_at,auto_stop_secs,auto_archive_secs,auto_delete_secs,max_age_secs,api_key_id,idle_secs,running_secs,
		size,limits,usage,enforcement`
	sandboxInsertPlaceholders = `?,?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?`
	// sandboxSelectCols/sandboxFrom go together: api_key_name comes from the api_keys
	// join, everything else is qualified so the join doesn't collide on `id`.
	sandboxSelectCols = `sandboxes.id,sandboxes.host_id,sandboxes.template,sandboxes.backend,sandboxes.workspace,sandboxes.pi_session,sandboxes.state,
		sandboxes.created_at,sandboxes.ready_at,sandboxes.isolation,sandboxes.name,sandboxes.labels,sandboxes.state_changed_at,
		sandboxes.auto_stop_secs,sandboxes.auto_archive_secs,sandboxes.auto_delete_secs,sandboxes.max_age_secs,
		sandboxes.api_key_id,COALESCE(ak.name,''),sandboxes.idle_secs,sandboxes.running_secs,
		sandboxes.size,sandboxes.limits,sandboxes.usage,sandboxes.enforcement`
	sandboxFrom = `FROM sandboxes LEFT JOIN api_keys ak ON sandboxes.api_key_id = ak.id`
)

func ptrToAny(p *uint64) any {
	if p == nil {
		return nil
	}
	return *p
}

// u64p converts a nullable INTEGER column to *uint64 (nil when NULL) — ptrToAny's inverse,
// for the AutoStopSecs/AutoArchiveSecs/AutoDeleteSecs/MaxAgeSecs columns.
func u64p(n sql.NullInt64) *uint64 {
	if !n.Valid {
		return nil
	}
	v := uint64(n.Int64)
	return &v
}

// sp converts a nullable TEXT column to *string (nil when NULL or empty).
func sp(n sql.NullString) *string {
	if !n.Valid || n.String == "" {
		return nil
	}
	v := n.String
	return &v
}

// sandboxInsertArgs builds the 17 bound values for sandboxInsertCols/Placeholders.
func sandboxInsertArgs(sb events.SandboxInfo, hostID string) ([]any, error) {
	var readyAt any
	if sb.ReadyAt != nil {
		readyAt = *sb.ReadyAt
	}
	var stateChangedAt any
	if sb.StateChangedAt != nil {
		stateChangedAt = *sb.StateChangedAt
	}
	labels := sb.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, err
	}
	// v5: limits/usage are pointers ({} when absent, per the schema default).
	limitsJSON, usageJSON := "{}", "{}"
	if sb.Limits != nil {
		b, err := json.Marshal(sb.Limits)
		if err != nil {
			return nil, err
		}
		limitsJSON = string(b)
	}
	if sb.Usage != nil {
		b, err := json.Marshal(sb.Usage)
		if err != nil {
			return nil, err
		}
		usageJSON = string(b)
	}
	return []any{
		sb.ID, hostID, sb.Template, sb.Backend, sb.WorkspacePath, sb.PiSession, sb.State, sb.CreatedAt, readyAt, sb.Isolation,
		sb.Name, string(labelsJSON), stateChangedAt, ptrToAny(sb.AutoStopSecs), ptrToAny(sb.AutoArchiveSecs), ptrToAny(sb.AutoDeleteSecs), ptrToAny(sb.MaxAgeSecs),
		sb.ApiKeyID, sb.IdleSecs, sb.RunningSecs,
		sb.Size, limitsJSON, usageJSON, sb.Enforcement,
	}, nil
}

func upsertSandboxTx(ctx context.Context, tx *sql.Tx, hostID string, sb events.SandboxInfo) error {
	args, err := sandboxInsertArgs(sb, hostID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO sandboxes(`+sandboxInsertCols+`)
		VALUES(`+sandboxInsertPlaceholders+`)
		ON CONFLICT(id) DO UPDATE SET host_id=excluded.host_id, template=excluded.template, backend=excluded.backend,
			workspace=excluded.workspace, pi_session=excluded.pi_session, state=excluded.state,
			ready_at=COALESCE(excluded.ready_at, sandboxes.ready_at),
			isolation=CASE WHEN excluded.isolation != '' THEN excluded.isolation ELSE sandboxes.isolation END,
			name=CASE WHEN excluded.name != '' THEN excluded.name ELSE sandboxes.name END,
			labels=CASE WHEN excluded.labels != '{}' THEN excluded.labels ELSE sandboxes.labels END,
			state_changed_at=COALESCE(excluded.state_changed_at, sandboxes.state_changed_at),
			auto_stop_secs=COALESCE(excluded.auto_stop_secs, sandboxes.auto_stop_secs),
			auto_archive_secs=COALESCE(excluded.auto_archive_secs, sandboxes.auto_archive_secs),
			auto_delete_secs=COALESCE(excluded.auto_delete_secs, sandboxes.auto_delete_secs),
			max_age_secs=COALESCE(excluded.max_age_secs, sandboxes.max_age_secs),
			api_key_id=CASE WHEN excluded.api_key_id != '' THEN excluded.api_key_id ELSE sandboxes.api_key_id END,
			idle_secs=excluded.idle_secs, running_secs=excluded.running_secs,
			size=CASE WHEN excluded.size != '' THEN excluded.size ELSE sandboxes.size END,
			limits=CASE WHEN excluded.limits != '{}' THEN excluded.limits ELSE sandboxes.limits END,
			usage=excluded.usage,
			enforcement=CASE WHEN excluded.enforcement != '' THEN excluded.enforcement ELSE sandboxes.enforcement END`,
		args...)
	return err
}

func (s *Store) ListHosts(ctx context.Context) ([]events.Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,url,backend,capacity,pool,last_seen,tiers,tls_fingerprint,policy,caps FROM hosts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []events.Host
	for rows.Next() {
		var h events.Host
		var poolJSON, tiersJSON, policyJSON, capsJSON string
		if err := rows.Scan(&h.ID, &h.URL, &h.Backend, &h.Capacity, &poolJSON, &h.LastSeen, &tiersJSON, &h.TLSFingerprint, &policyJSON, &capsJSON); err != nil {
			return nil, err
		}
		h.Pool = decodePool(h.ID, poolJSON)
		_ = json.Unmarshal([]byte(tiersJSON), &h.Tiers)
		h.Policy = json.RawMessage(policyJSON)
		_ = json.Unmarshal([]byte(capsJSON), &h.Caps)
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) GetHost(ctx context.Context, id string) (*events.Host, error) {
	var h events.Host
	var poolJSON, tiersJSON, policyJSON, capsJSON string
	err := s.db.QueryRowContext(ctx, `SELECT id,url,backend,capacity,pool,last_seen,tiers,tls_fingerprint,policy,caps FROM hosts WHERE id=?`, id).
		Scan(&h.ID, &h.URL, &h.Backend, &h.Capacity, &poolJSON, &h.LastSeen, &tiersJSON, &h.TLSFingerprint, &policyJSON, &capsJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	h.Pool = decodePool(h.ID, poolJSON)
	_ = json.Unmarshal([]byte(tiersJSON), &h.Tiers)
	h.Policy = json.RawMessage(policyJSON)
	_ = json.Unmarshal([]byte(capsJSON), &h.Caps)
	return &h, nil
}

func decodePool(hostID, s string) events.PoolStats {
	var p events.PoolStats
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		slog.Default().Warn("malformed pool JSON degrades to empty", "host_id", hostID, "err", err)
	}
	return p
}

// ---- sandboxes

func (s *Store) CreateSandbox(ctx context.Context, sb events.SandboxInfo, hostID string) error {
	args, err := sandboxInsertArgs(sb, hostID)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sandboxes(`+sandboxInsertCols+`) VALUES(`+sandboxInsertPlaceholders+`)`, args...)
	return err
}

// ListSandboxes filters by state, a "k=v" label match, exact name, and/or the API key
// that created it; any of the four may be empty to skip that filter.
func (s *Store) ListSandboxes(ctx context.Context, state, label, name, apiKeyID string) ([]events.SandboxInfo, error) {
	q := `SELECT ` + sandboxSelectCols + ` ` + sandboxFrom + ` WHERE 1=1`
	args := []any{}
	if state != "" {
		q += ` AND sandboxes.state=?`
		args = append(args, state)
	}
	if name != "" {
		q += ` AND sandboxes.name=?`
		args = append(args, name)
	}
	if apiKeyID != "" {
		q += ` AND sandboxes.api_key_id=?`
		args = append(args, apiKeyID)
	}
	if k, v, ok := strings.Cut(label, "="); ok {
		q += ` AND json_extract(sandboxes.labels, ?) = ?`
		args = append(args, "$."+k, v)
	}
	q += ` ORDER BY sandboxes.created_at DESC`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSandboxes(rows)
}

func (s *Store) GetSandbox(ctx context.Context, id string) (*events.SandboxInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sandboxSelectCols+` `+sandboxFrom+` WHERE sandboxes.id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := scanSandboxes(rows)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return &list[0], nil
}

func scanSandboxes(rows *sql.Rows) ([]events.SandboxInfo, error) {
	out := []events.SandboxInfo{} // never nil: the dashboard indexes this
	for rows.Next() {
		var sb events.SandboxInfo
		var readyAt, stateChangedAt sql.NullString
		var labelsJSON, limitsJSON, usageJSON string
		var autoStop, autoArchive, autoDelete, maxAge sql.NullInt64
		if err := rows.Scan(&sb.ID, &sb.HostID, &sb.Template, &sb.Backend, &sb.WorkspacePath, &sb.PiSession, &sb.State, &sb.CreatedAt, &readyAt, &sb.Isolation,
			&sb.Name, &labelsJSON, &stateChangedAt, &autoStop, &autoArchive, &autoDelete, &maxAge, &sb.ApiKeyID, &sb.ApiKeyName, &sb.IdleSecs, &sb.RunningSecs,
			&sb.Size, &limitsJSON, &usageJSON, &sb.Enforcement); err != nil {
			return nil, err
		}
		if limitsJSON != "" && limitsJSON != "{}" {
			var l events.SandboxLimits
			if json.Unmarshal([]byte(limitsJSON), &l) == nil {
				sb.Limits = &l
			}
		}
		if usageJSON != "" && usageJSON != "{}" {
			var u events.SandboxUsage
			if json.Unmarshal([]byte(usageJSON), &u) == nil {
				sb.Usage = &u
			}
		}
		sb.ReadyAt = sp(readyAt)
		sb.StateChangedAt = sp(stateChangedAt)
		sb.Labels = map[string]string{}
		if err := json.Unmarshal([]byte(labelsJSON), &sb.Labels); err != nil {
			slog.Default().Warn("malformed labels JSON degrades to empty", "sandbox_id", sb.ID, "err", err)
		}
		sb.AutoStopSecs = u64p(autoStop)
		sb.AutoArchiveSecs = u64p(autoArchive)
		sb.AutoDeleteSecs = u64p(autoDelete)
		sb.MaxAgeSecs = u64p(maxAge)
		out = append(out, sb)
	}
	return out, rows.Err()
}

// CommittedByHost is Sigma Limits (cpus, mem_mib) of each host's live sandboxes
// (creating|ready|busy|paused — the states that hold a slot; docs/protocol.md §3a v5),
// for GET /api/hosts' Host.committed, GET /metrics' sbxcp_host_committed_* gauges, and
// registry.PickHostForRequest's fit filter.
func (s *Store) CommittedByHost(ctx context.Context) (map[string]events.HostCommitted, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host_id, COALESCE(SUM(json_extract(limits,'$.cpus')),0), COALESCE(SUM(json_extract(limits,'$.mem_mib')),0)
		FROM sandboxes WHERE state IN ('creating','ready','busy','paused') GROUP BY host_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]events.HostCommitted{}
	for rows.Next() {
		var hostID string
		var c events.HostCommitted
		if err := rows.Scan(&hostID, &c.Cpus, &c.MemMiB); err != nil {
			return nil, err
		}
		out[hostID] = c
	}
	return out, rows.Err()
}

// execer is satisfied by both *sql.DB and *sql.Tx, so UpdateSandboxState runs the same way
// inside an existing transaction (InsertEvents' batch) or standalone (SetSandboxState).
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// UpdateSandboxState applies a state transition (used when ingesting sandbox.ready|
// destroyed|stopped|started|paused|resumed|archived events, and directly by
// SetSandboxState).
func UpdateSandboxState(ctx context.Context, x execer, id, state string) error {
	switch state {
	case "ready", "busy", "paused", "stopped", "archived":
		_, err := x.ExecContext(ctx, `UPDATE sandboxes SET state=?, state_changed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
			ready_at=CASE WHEN ?='ready' THEN COALESCE(ready_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ELSE ready_at END
			WHERE id=?`, state, state, id)
		return err
	case "destroyed":
		_, err := x.ExecContext(ctx, `UPDATE sandboxes SET state='destroyed', destroyed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), state_changed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`, id)
		return err
	}
	return nil
}

// SetSandboxState is UpdateSandboxState against the store directly, for the stop/start/
// pause/resume/archive API handlers to apply the daemon's reply — a single UPDATE is
// already atomic, so no transaction wrapper is needed here.
func (s *Store) SetSandboxState(ctx context.Context, id, state string) error {
	return UpdateSandboxState(ctx, s.db, id, state)
}

// ---- events

// InsertEvents inserts a batch in one transaction and updates sandbox state from
// sandbox.ready|destroyed events.
func (s *Store) InsertEvents(ctx context.Context, evs []events.Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO events(id,ts,host_id,sandbox_id,pi_session,tool_call_id,type,data) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	ftsStmt, err := tx.PrepareContext(ctx, `INSERT INTO events_fts(id,ts,data) VALUES(?,?,?)`)
	if err != nil {
		return err
	}
	defer ftsStmt.Close()

	for _, e := range evs {
		res, err := stmt.ExecContext(ctx, e.ID, e.TS, e.HostID, e.SandboxID, e.PiSession, e.ToolCallID, e.Type, string(e.Data))
		if err != nil {
			return err
		}
		// events_fts has no UNIQUE constraint (FTS5 virtual tables can't declare one), so
		// only index rows the INSERT OR IGNORE above actually inserted — otherwise a
		// retried batch would duplicate this event in search results.
		if n, _ := res.RowsAffected(); n > 0 {
			if _, err := ftsStmt.ExecContext(ctx, e.ID, e.TS, string(e.Data)); err != nil {
				return err
			}
		}
		switch e.Type {
		case events.SandboxReady, events.SandboxStarted, events.SandboxResumed:
			if err := UpdateSandboxState(ctx, tx, e.SandboxID, "ready"); err != nil {
				return err
			}
		case events.SandboxDestroyed:
			if err := UpdateSandboxState(ctx, tx, e.SandboxID, "destroyed"); err != nil {
				return err
			}
		case events.SandboxStopped:
			if err := UpdateSandboxState(ctx, tx, e.SandboxID, "stopped"); err != nil {
				return err
			}
		case events.SandboxPaused:
			if err := UpdateSandboxState(ctx, tx, e.SandboxID, "paused"); err != nil {
				return err
			}
		case events.SandboxArchived:
			if err := UpdateSandboxState(ctx, tx, e.SandboxID, "archived"); err != nil {
				return err
			}
		case events.SandboxUsageEvent:
			// v5.1 (docs/protocol.md §3a): the guest agent pushes this every ~2s while an
			// exec is live — fresher than the ~10s heartbeat, which stays the fallback for
			// idle sandboxes that never exec.
			var usage events.SandboxUsage
			if err := json.Unmarshal(e.Data, &usage); err != nil {
				slog.Default().Warn("malformed sandbox.usage JSON ignored", "sandbox_id", e.SandboxID, "err", err)
				continue
			}
			if err := updateSandboxUsage(ctx, tx, e.SandboxID, usage); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// updateSandboxUsage stores usage as the sandbox row's usage column.
func updateSandboxUsage(ctx context.Context, x execer, id string, usage events.SandboxUsage) error {
	b, err := json.Marshal(usage)
	if err != nil {
		return err
	}
	_, err = x.ExecContext(ctx, `UPDATE sandboxes SET usage=? WHERE id=?`, string(b), id)
	return err
}

func (s *Store) ListEventsForSandbox(ctx context.Context, sandboxID, after string, limit int) ([]events.Event, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id,ts,host_id,sandbox_id,pi_session,tool_call_id,type,data FROM events
		WHERE sandbox_id=? AND id>? ORDER BY id ASC LIMIT ?`, sandboxID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (s *Store) ListEgressEvents(ctx context.Context, limit int, piSession, sandboxID string) ([]events.Event, error) {
	if limit <= 0 {
		limit = 500
	}
	q := `SELECT id,ts,host_id,sandbox_id,pi_session,tool_call_id,type,data FROM events
		WHERE type IN ('egress.allow','egress.deny')`
	args := []any{}
	if piSession != "" {
		q += ` AND pi_session=?`
		args = append(args, piSession)
	}
	if sandboxID != "" {
		q += ` AND sandbox_id=?`
		args = append(args, sandboxID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]events.Event, error) {
	var out []events.Event
	for rows.Next() {
		var e events.Event
		var data string
		if err := rows.Scan(&e.ID, &e.TS, &e.HostID, &e.SandboxID, &e.PiSession, &e.ToolCallID, &e.Type, &data); err != nil {
			return nil, err
		}
		e.Data = json.RawMessage(data)
		out = append(out, e)
	}
	return out, rows.Err()
}
