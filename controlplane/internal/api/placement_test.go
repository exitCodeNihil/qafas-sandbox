// placement_test.go: end-to-end table test for POST /api/sandboxes placement (v4,
// docs/protocol.md §4/§4b, docs/decisions.md D25) — validation, tier resolution (explicit,
// auto, allowed_tiers), template/snapshot narrowing, and daemon-error passthrough.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

// placementHostSpec describes one fake qafas host for the table below.
type placementHostSpec struct {
	id        string
	tiers     []string
	snapshots map[string]string // snapshot name -> state; a name absent here is "missing"
	// createStatus/createBody, when createStatus != 0, override the normal 201 success
	// reply — used to exercise the daemon-error-passes-through case.
	createStatus int
	createBody   string
}

// newPlacementHost seeds a fakeQafas from spec and registers it with mux as spec.id/tiers.
func newPlacementHost(t *testing.T, mux *http.ServeMux, spec placementHostSpec) {
	t.Helper()
	fake := newFakeHost(t, mux, spec.id, spec.tiers)
	for name, state := range spec.snapshots {
		fake.seedSnapshot(name, state)
	}
	if spec.createStatus != 0 {
		fake.overrideCreate(spec.createStatus, spec.createBody)
	}
}

func TestPlacementTable(t *testing.T) {
	cases := []struct {
		name             string
		hosts            []placementHostSpec
		keyLimits        *events.ApiKeyLimits
		req              events.CreateSandboxReq
		wantStatus       int
		wantHostID       string   // when set, the created sandbox's host_id must equal this
		wantBodyContains []string // substrings the response body must contain
	}{
		{
			name:       "explicit tier present",
			hosts:      []placementHostSpec{{id: "h1", tiers: []string{"vm"}}},
			req:        events.CreateSandboxReq{PiSession: "t", Isolation: "vm"},
			wantStatus: http.StatusCreated,
			wantHostID: "h1",
		},
		{
			name:             "explicit tier absent",
			hosts:            []placementHostSpec{{id: "h1", tiers: []string{"vm"}}},
			req:              events.CreateSandboxReq{PiSession: "t", Isolation: "native"},
			wantStatus:       http.StatusConflict,
			wantBodyContains: []string{"no host serves the native runtime"},
		},
		{
			name: "auto trusted picks remote first",
			hosts: []placementHostSpec{
				{id: "hnative", tiers: []string{"native"}},
				{id: "hvm", tiers: []string{"vm"}},
				{id: "hremote", tiers: []string{"remote"}},
			},
			req:        events.CreateSandboxReq{PiSession: "t"},
			wantStatus: http.StatusCreated,
			wantHostID: "hremote",
		},
		{
			name:       "auto untrusted with only a native host",
			hosts:      []placementHostSpec{{id: "hnative", tiers: []string{"native"}}},
			req:        events.CreateSandboxReq{PiSession: "t", Trust: "untrusted"},
			wantStatus: http.StatusConflict,
		},
		{
			name: "allowed_tiers [remote] plus unset resolves remote",
			hosts: []placementHostSpec{
				{id: "hremote", tiers: []string{"remote"}},
				{id: "hnative", tiers: []string{"native"}},
			},
			keyLimits:  &events.ApiKeyLimits{AllowedTiers: []string{"remote"}},
			req:        events.CreateSandboxReq{PiSession: "t"},
			wantStatus: http.StatusCreated,
			wantHostID: "hremote",
		},
		{
			name:             "allowed_tiers [vm] plus explicit remote is forbidden",
			hosts:            []placementHostSpec{{id: "hremote", tiers: []string{"remote"}}},
			keyLimits:        &events.ApiKeyLimits{AllowedTiers: []string{"vm"}},
			req:              events.CreateSandboxReq{PiSession: "t", Isolation: "remote"},
			wantStatus:       http.StatusForbidden,
			wantBodyContains: []string{"this key may use tiers"},
		},
		{
			name: "template active on one of two hosts wins",
			hosts: []placementHostSpec{
				{id: "hbuilding", tiers: []string{"vm"}, snapshots: map[string]string{"snap1": "building"}},
				{id: "hactive", tiers: []string{"vm"}, snapshots: map[string]string{"snap1": "active"}},
			},
			req:        events.CreateSandboxReq{PiSession: "t", Isolation: "vm", Template: "snap1"},
			wantStatus: http.StatusCreated,
			wantHostID: "hactive",
		},
		{
			name: "template building everywhere names every host",
			hosts: []placementHostSpec{
				{id: "ha", tiers: []string{"vm"}, snapshots: map[string]string{"snap1": "building"}},
				{id: "hb", tiers: []string{"vm"}}, // no snap1 at all -> "missing"
			},
			req:              events.CreateSandboxReq{PiSession: "t", Isolation: "vm", Template: "snap1"},
			wantStatus:       http.StatusConflict,
			wantBodyContains: []string{"snap1", "ha=building", "hb=missing"},
		},
		{
			name: "template that exists nowhere is 404, like the daemon",
			hosts: []placementHostSpec{
				{id: "ha", tiers: []string{"vm"}},
				{id: "hb", tiers: []string{"remote"}},
			},
			req:              events.CreateSandboxReq{PiSession: "t", Isolation: "vm", Template: "nope"},
			wantStatus:       http.StatusNotFound,
			wantBodyContains: []string{"unknown template", "nope"},
		},
		{
			name: "template active only on another tier's host is 409 naming it",
			hosts: []placementHostSpec{
				{id: "ha", tiers: []string{"vm"}},
				{id: "hb", tiers: []string{"remote"}, snapshots: map[string]string{"snap1": "active"}},
			},
			req:              events.CreateSandboxReq{PiSession: "t", Isolation: "vm", Template: "snap1"},
			wantStatus:       http.StatusConflict,
			wantBodyContains: []string{"ha=missing", "hb=active"},
		},
		{
			name: "daemon error passes through unchanged",
			hosts: []placementHostSpec{{
				id: "h1", tiers: []string{"vm"},
				createStatus: http.StatusConflict, createBody: `{"error":"daemon says no"}`,
			}},
			req:              events.CreateSandboxReq{PiSession: "t", Isolation: "vm"},
			wantStatus:       http.StatusConflict,
			wantBodyContains: []string{"daemon says no"},
		},
		{
			name:       "isolation alias firecracker accepted",
			hosts:      []placementHostSpec{{id: "hremote", tiers: []string{"remote"}}},
			req:        events.CreateSandboxReq{PiSession: "t", Isolation: "firecracker"},
			wantStatus: http.StatusCreated,
			wantHostID: "hremote",
		},
		{
			name:       "isolation kvm is not an alias",
			req:        events.CreateSandboxReq{PiSession: "t", Isolation: "kvm"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "bad name is rejected",
			req:        events.CreateSandboxReq{PiSession: "t", Name: strPtr("Not Valid!")},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, mux := newTestAPI(t)
			for _, h := range c.hosts {
				newPlacementHost(t, mux, h)
			}
			token := testAdmin
			if c.keyLimits != nil {
				key := createApiKey(t, mux, events.CreateApiKeyReq{Name: fmt.Sprintf("k-%s", c.name), Scopes: []string{"sandboxes"}, Limits: *c.keyLimits})
				token = key.Key
			}
			rec := doReq(mux, "POST", "/api/sandboxes", token, c.req)
			if rec.Code != c.wantStatus {
				t.Fatalf("status: got %d, want %d: %s", rec.Code, c.wantStatus, rec.Body.String())
			}
			if c.wantHostID != "" {
				var resp events.CreateSandboxResp
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode: %v: %s", err, rec.Body.String())
				}
				if resp.HostID != c.wantHostID {
					t.Fatalf("host_id: got %q, want %q", resp.HostID, c.wantHostID)
				}
			}
			for _, sub := range c.wantBodyContains {
				if !strings.Contains(rec.Body.String(), sub) {
					t.Fatalf("body %q missing %q", rec.Body.String(), sub)
				}
			}
		})
	}
}

func strPtr(s string) *string { return &s }
