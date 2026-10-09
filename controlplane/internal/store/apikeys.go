// apikeys.go: v3 API keys (docs/protocol.md §4b) — one table, no joins needed except the
// sandboxes.api_key_id join already added in store.go for SandboxInfo/SessionSummary.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

// Key shape: sbx_<prefix>_<secret> (docs/protocol.md §4b, lengths frozen there). The prefix
// is stored and shown; only the secret's sha256 is stored, the full key is returned once at
// creation.
const (
	keyPrefixLen      = 8
	keySecretLen      = 32
	liveSandboxStates = `'creating','ready','busy','paused','stopped','archived'` // creating counts: the row exists before the first heartbeat
)

// randomString returns n lowercased characters of crypto/rand.Text()'s own alphabet
// (Crockford base32: digits and A-Z minus I/L/O/U) — plenty of entropy for either an
// 8-char prefix or a 32-char secret, no math/big rejection sampling needed.
func randomString(n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(rand.Text())
	}
	return strings.ToLower(b.String()[:n])
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// CreateApiKey generates a new key, stores its sha256 (never the key itself), and returns
// the created row plus the key string (shown only this once).
func (s *Store) CreateApiKey(ctx context.Context, req events.CreateApiKeyReq) (*events.ApiKeyCreated, error) {
	prefix := randomString(keyPrefixLen)
	key := "sbx_" + prefix + "_" + randomString(keySecretLen)

	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, err
	}
	limitsJSON, err := json.Marshal(req.Limits)
	if err != nil {
		return nil, err
	}
	labels := req.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return nil, err
	}

	id := events.NewULID()
	_, err = s.db.ExecContext(ctx, `INSERT INTO api_keys(id,name,prefix,secret_sha256,scopes,limits,labels,created_at)
		VALUES(?,?,?,?,?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
		id, req.Name, prefix, sha256Hex(key), string(scopesJSON), string(limitsJSON), string(labelsJSON))
	if err != nil {
		return nil, err
	}

	ak, err := s.GetApiKey(ctx, id)
	if err != nil {
		return nil, err
	}
	if ak == nil {
		return nil, fmt.Errorf("api key %s vanished after insert", id)
	}
	return &events.ApiKeyCreated{ApiKey: *ak, Key: key}, nil
}

func scanApiKey(row interface {
	Scan(...any) error
}) (*events.ApiKey, error) {
	var ak events.ApiKey
	var scopesJSON, limitsJSON, labelsJSON string
	var lastUsed, revoked sql.NullString
	if err := row.Scan(&ak.ID, &ak.Name, &ak.Prefix, &scopesJSON, &limitsJSON, &labelsJSON, &ak.CreatedAt, &lastUsed, &revoked); err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(scopesJSON), &ak.Scopes)
	_ = json.Unmarshal([]byte(limitsJSON), &ak.Limits)
	ak.Labels = map[string]string{}
	_ = json.Unmarshal([]byte(labelsJSON), &ak.Labels)
	if lastUsed.Valid {
		v := lastUsed.String
		ak.LastUsedAt = &v
	}
	if revoked.Valid {
		v := revoked.String
		ak.RevokedAt = &v
	}
	return &ak, nil
}

const apiKeySelectCols = `id,name,prefix,scopes,limits,labels,created_at,last_used_at,revoked_at`

// GetApiKey returns one key by id (nil if it doesn't exist), with live_sandboxes/
// created_24h filled in. Revocation is not filtered here — callers that must reject a
// revoked key (auth) check RevokedAt themselves; GET /api/keys/{id} still shows it.
func (s *Store) GetApiKey(ctx context.Context, id string) (*events.ApiKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+apiKeySelectCols+` FROM api_keys WHERE id=?`, id)
	ak, err := scanApiKey(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	live, created24h, err := s.apiKeyCounts(ctx, id)
	if err != nil {
		return nil, err
	}
	ak.LiveSandboxes, ak.Created24h = live, created24h
	return ak, nil
}

// ListApiKeys returns every key, newest first, each with live_sandboxes/created_24h filled in.
func (s *Store) ListApiKeys(ctx context.Context) ([]events.ApiKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+apiKeySelectCols+` FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []events.ApiKey{}
	var ids []string
	for rows.Next() {
		ak, err := scanApiKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ak)
		ids = append(ids, ak.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		live, created24h, err := s.apiKeyCounts(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].LiveSandboxes, out[i].Created24h = live, created24h
	}
	return out, nil
}

// RevokeApiKey sets revoked_at (idempotent: a key already revoked stays revoked and this
// still reports found=true). found=false means no such key.
func (s *Store) RevokeApiKey(ctx context.Context, id string) (found bool, err error) {
	res, err := s.db.ExecContext(ctx, `UPDATE api_keys SET revoked_at=COALESCE(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ','now')) WHERE id=?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// DeleteApiKey hard-deletes the row. Called on a key that's already revoked (defect: a
// second DELETE just re-set the same revoked_at and the row sat there forever) —
// sandboxes it created keep sandboxes.api_key_id pointing at a since-deleted id, which
// the LEFT JOINs in store.go/apikeys.go already tolerate via COALESCE(ak.name,”).
func (s *Store) DeleteApiKey(ctx context.Context, id string) (found bool, err error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id=?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// LookupApiKeyBySecret parses "sbx_<prefix>_<secret>", finds the row by prefix (cheap,
// indexed, and reveals nothing about the secret), then compares the secret's sha256
// against the stored hash in constant time so a timing side-channel can't help an
// attacker who already knows a valid prefix guess the secret. Returns nil (no error) for
// a malformed key or a prefix that doesn't exist.
func (s *Store) LookupApiKeyBySecret(ctx context.Context, key string) (*events.ApiKey, error) {
	rest, ok := strings.CutPrefix(key, "sbx_")
	if !ok {
		return nil, nil
	}
	prefix, _, ok := strings.Cut(rest, "_")
	if !ok || prefix == "" {
		return nil, nil
	}
	var id, storedHash string
	err := s.db.QueryRowContext(ctx, `SELECT id, secret_sha256 FROM api_keys WHERE prefix=?`, prefix).Scan(&id, &storedHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(sha256Hex(key)), []byte(storedHash)) != 1 {
		return nil, nil
	}
	return s.GetApiKey(ctx, id)
}

// TouchApiKeyLastUsed bumps last_used_at, but at most once per 30s per key — design:
// a single UPDATE...WHERE guard rather than a separate in-memory rate limiter; good
// enough since it only trades a few seconds of staleness on last_used_at for one fewer
// write per request.
func (s *Store) TouchApiKeyLastUsed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
		WHERE id=? AND (last_used_at IS NULL OR julianday('now') - julianday(last_used_at) >= 30.0/86400.0)`, id)
	return err
}

// apiKeyCounts is live sandboxes now + sandboxes created in the last 24h, for ApiKey.LiveSandboxes/Created24h.
func (s *Store) apiKeyCounts(ctx context.Context, id string) (live, created24h int, err error) {
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandboxes WHERE api_key_id=? AND state IN (`+liveSandboxStates+`)`, id).Scan(&live); err != nil {
		return 0, 0, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandboxes WHERE api_key_id=? AND julianday(created_at) >= julianday('now','-24 hours')`, id).Scan(&created24h)
	return live, created24h, err
}

// ApiKeyLimitCounts is what POST /api/sandboxes needs to enforce ApiKeyLimits.MaxConcurrent/
// MaxPerHour: live sandboxes now, and sandboxes created by this key in the last hour.
func (s *Store) ApiKeyLimitCounts(ctx context.Context, id string) (live, createdLastHour int, err error) {
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandboxes WHERE api_key_id=? AND state IN (`+liveSandboxStates+`)`, id).Scan(&live); err != nil {
		return 0, 0, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandboxes WHERE api_key_id=? AND julianday(created_at) >= julianday('now','-1 hours')`, id).Scan(&createdLastHour)
	return live, createdLastHour, err
}

// eventColumnSince runs `SELECT col FROM events WHERE <typeFilter> AND sandbox_id IN
// (sandboxIDs) AND julianday(ts) >= julianday(since)` and returns every value of col — the
// shape shared by ApiKeyUsage's alert/egress breakdowns.
func (s *Store) eventColumnSince(ctx context.Context, col, typeFilter string, sandboxIDArgs []any, since string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+col+` FROM events WHERE `+typeFilter+` AND sandbox_id IN (`+placeholders(len(sandboxIDArgs))+`) AND julianday(ts) >= julianday(?)`,
		append(append([]any{}, sandboxIDArgs...), since)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ApiKeyUsage computes docs/protocol.md §4b's ApiKeyUsage for one key since the given
// RFC3339 cutoff: sandbox_seconds and by_tier come straight from the sandboxes table;
// execs/alerts/egress are events joined on this key's sandbox ids.
func (s *Store) ApiKeyUsage(ctx context.Context, id, since string) (*events.ApiKeyUsage, error) {
	usage := &events.ApiKeyUsage{Since: since, Alerts: map[string]int{}, Egress: map[string]int{}, ByTier: map[string]int{}}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandboxes WHERE api_key_id=? AND julianday(created_at) >= julianday(?)`, id, since).
		Scan(&usage.SandboxesCreated); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sandboxes WHERE api_key_id=? AND state IN (`+liveSandboxStates+`)`, id).
		Scan(&usage.LiveSandboxes); err != nil {
		return nil, err
	}
	// sandbox_seconds = sum over the key's sandboxes of (destroyed_at or now) - created_at.
	// julianday() parses either timestamp format this codebase uses (strftime-with-millis
	// or the plain RFC3339 qafas/api.go write) so this needs no Go-side time parsing.
	var seconds sql.NullFloat64
	if err := s.db.QueryRowContext(ctx, `SELECT SUM((julianday(COALESCE(destroyed_at, strftime('%Y-%m-%dT%H:%M:%fZ','now'))) - julianday(created_at)) * 86400.0)
		FROM sandboxes WHERE api_key_id=?`, id).Scan(&seconds); err != nil {
		return nil, err
	}
	usage.SandboxSeconds = seconds.Float64

	tierRows, err := s.db.QueryContext(ctx, `SELECT isolation, COUNT(*) FROM sandboxes WHERE api_key_id=? GROUP BY isolation`, id)
	if err != nil {
		return nil, err
	}
	for tierRows.Next() {
		var tier string
		var n int
		if err := tierRows.Scan(&tier, &n); err != nil {
			tierRows.Close()
			return nil, err
		}
		if tier != "" {
			usage.ByTier[tier] = n
		}
	}
	if err := tierRows.Err(); err != nil {
		tierRows.Close()
		return nil, err
	}
	tierRows.Close()

	var sandboxIDs []string
	idRows, err := s.db.QueryContext(ctx, `SELECT id FROM sandboxes WHERE api_key_id=?`, id)
	if err != nil {
		return nil, err
	}
	for idRows.Next() {
		var sbid string
		if err := idRows.Scan(&sbid); err != nil {
			idRows.Close()
			return nil, err
		}
		sandboxIDs = append(sandboxIDs, sbid)
	}
	if err := idRows.Err(); err != nil {
		idRows.Close()
		return nil, err
	}
	idRows.Close()

	if len(sandboxIDs) > 0 {
		args := make([]any, 0, len(sandboxIDs)+1)
		for _, sbid := range sandboxIDs {
			args = append(args, sbid)
		}
		in := placeholders(len(sandboxIDs))

		execArgs := append(append([]any{}, args...), since)
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE type='exec.start' AND sandbox_id IN (`+in+`) AND julianday(ts) >= julianday(?)`, execArgs...).
			Scan(&usage.Execs); err != nil {
			return nil, err
		}

		alertData, err := s.eventColumnSince(ctx, "data", "type='security.alert'", args, since)
		if err != nil {
			return nil, err
		}
		for _, data := range alertData {
			var ad events.AlertData
			if json.Unmarshal([]byte(data), &ad) == nil {
				usage.Alerts[ad.Severity]++
			}
		}

		egressTypes, err := s.eventColumnSince(ctx, "type", "type IN ('egress.allow','egress.deny')", args, since)
		if err != nil {
			return nil, err
		}
		for _, typ := range egressTypes {
			usage.Egress[strings.TrimPrefix(typ, "egress.")]++
		}
	}

	var lastUsed sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT last_used_at FROM api_keys WHERE id=?`, id).Scan(&lastUsed); err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if lastUsed.Valid {
		v := lastUsed.String
		usage.LastUsedAt = &v
	}
	return usage, nil
}
