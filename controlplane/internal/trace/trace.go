// Package trace maps a session's events onto an OpenTelemetry-shaped trace
// (docs/protocol.md §1.2). Storage stays SQLite; this is a read-side projection used by
// GET /api/sessions/{id}/trace and the OTLP push in internal/otlp. No OTel SDK dependency
// (docs/decisions.md D20): OTLP/JSON is just a struct.
package trace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

// ---- OTLP/JSON shapes (opentelemetry-proto trace v1, JSON encoding: int64 as string).

type AnyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"`
	BoolValue   *bool   `json:"boolValue,omitempty"`
}

type KeyValue struct {
	Key   string   `json:"key"`
	Value AnyValue `json:"value"`
}

func strAttr(k, v string) KeyValue { return KeyValue{k, AnyValue{StringValue: &v}} }
func intAttr(k string, v int64) KeyValue {
	s := strconv.FormatInt(v, 10)
	return KeyValue{k, AnyValue{IntValue: &s}}
}

type SpanEvent struct {
	TimeUnixNano string     `json:"timeUnixNano"`
	Name         string     `json:"name"`
	Attributes   []KeyValue `json:"attributes,omitempty"`
}

// SpanKind values (opentelemetry-proto): 1 = INTERNAL.
const KindInternal = 1

type Span struct {
	TraceID           string      `json:"traceId"`
	SpanID            string      `json:"spanId"`
	ParentSpanID      string      `json:"parentSpanId,omitempty"`
	Name              string      `json:"name"`
	Kind              int         `json:"kind"`
	StartTimeUnixNano string      `json:"startTimeUnixNano"`
	EndTimeUnixNano   string      `json:"endTimeUnixNano,omitempty"`
	Attributes        []KeyValue  `json:"attributes,omitempty"`
	Events            []SpanEvent `json:"events,omitempty"`

	Completed bool `json:"-"` // has both start and end; used by the OTLP pusher (internal/otlp)
}

type scopeSpansScope struct {
	Name string `json:"name"`
}

type ScopeSpans struct {
	Scope scopeSpansScope `json:"scope"`
	Spans []Span          `json:"spans"`
}

type Resource struct {
	Attributes []KeyValue `json:"attributes"`
}

type ResourceSpans struct {
	Resource   Resource     `json:"resource"`
	ScopeSpans []ScopeSpans `json:"scopeSpans"`
}

// ExportTraceServiceRequest is the OTLP/JSON trace export envelope.
type ExportTraceServiceRequest struct {
	ResourceSpans []ResourceSpans `json:"resourceSpans"`
}

// TraceID returns hex(sha256(pi_session)[:16]) — a standard 16-byte/32-hex-char OTLP trace id.
func TraceID(piSession string) string {
	sum := sha256.Sum256([]byte(piSession))
	return hex.EncodeToString(sum[:16])
}

// spanIDFrom returns hex(sha256(seed)[:8]) — a standard 8-byte/16-hex-char OTLP span id.
func spanIDFrom(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:8])
}

func unixNano(ts string) (int64, bool) {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return 0, false
	}
	return t.UnixNano(), true
}

func firstWord(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return "exec"
	}
	return fields[0]
}

type execKey struct{ sandbox, tool string }
type procKey struct{ sandbox, pid string }

// fsSpanName maps a non-exec tool-call event type to its span name (protocol.md §1.2):
// "fs.write"/"fs.read"/"fs.edit" for the corresponding file.* event, unchanged for
// browser.navigate.
func fsSpanName(eventType string) string {
	switch eventType {
	case events.FileRead:
		return "fs.read"
	case events.FileWrite:
		return "fs.write"
	case events.FileEdit:
		return "fs.edit"
	default:
		return eventType // browser.navigate
	}
}

const sessionRootSpanName = "session"

// BuildSpans assembles the spans for one session's events (already filtered to that
// pi_session, any order — this sorts by ts internally):
//
//   - one span per tool call with an exec: exec.start -> exec.end paired by tool_call_id
//     (falling back to the exec.start event's own id when tool_call_id is empty, e.g.
//     user_bash, so it still gets a stable, unique span);
//   - one span per tool call WITHOUT an exec (a file.read/file.write/file.edit through
//     /fs/*, or browser.navigate — the read/write/edit/browser tools never exec): name =
//     the (mapped) event type, start/end = the first/last event's ts for that
//     tool_call_id (minimum 1ms);
//   - a child span per process: process.start -> process.exit paired by (sandbox_id, pid),
//     attributed to the exec span by tool_call_id, or — when the process event carries no
//     tool_call_id (telemetry samples independently of the request) — by root_pid, learned
//     from whichever process.start for that root_pid *did* carry one;
//   - a synthetic "session" root span, always present, spanning the whole event set;
//   - span events for file.access/net.connect/egress.*/security.alert, attached to the
//     span matching tool_call_id (exec or fs/browser), or — when tool_call_id is empty —
//     the synthetic session root span.
//
// The caller fetches evs in bounded pages (store.ListAllSessionEvents) and passes the
// assembled slice in one call; BuildSpans itself is a single in-memory pass plus small
// fixups over that slice.
func BuildSpans(piSession string, evs []events.Event) []Span {
	sorted := make([]events.Event, len(evs))
	copy(sorted, evs)
	sortByTS(sorted)

	traceID := TraceID(piSession)
	execSpans := map[execKey]*Span{}
	var execOrder []execKey

	// Tool calls that only did fs/browser work (no exec). Built in a second pass, once
	// every exec.start is known, so we can skip tool_call_ids an exec span already covers.
	fsEvents := map[execKey][]events.Event{}
	var fsOrder []execKey
	fsSpans := map[execKey]*Span{}

	procSpans := map[procKey]*Span{}
	var procOrder []procKey
	procParentTool := map[procKey]string{}
	rootPidToTool := map[[2]string]string{} // [sandbox,root_pid] -> tool_call_id

	var spanEvents []events.Event
	var minTS, maxTS string

	for _, e := range sorted {
		if minTS == "" || e.TS < minTS {
			minTS = e.TS
		}
		if e.TS > maxTS {
			maxTS = e.TS
		}
		switch e.Type {
		case events.ExecStart:
			var data struct {
				Cmd string `json:"cmd"`
				Cwd string `json:"cwd"`
			}
			_ = json.Unmarshal(e.Data, &data)
			seed := e.ToolCallID
			if seed == "" {
				seed = e.ID
			}
			sp := &Span{
				TraceID: traceID,
				SpanID:  spanIDFrom(seed),
				Name:    firstWord(data.Cmd),
				Kind:    KindInternal,
				Attributes: []KeyValue{
					strAttr("session.id", piSession),
					strAttr("sbx.sandbox_id", e.SandboxID),
					strAttr("sbx.host_id", e.HostID),
					strAttr("process.command_line", data.Cmd),
					strAttr("sbx.cwd", data.Cwd),
				},
			}
			if n, ok := unixNano(e.TS); ok {
				sp.StartTimeUnixNano = strconv.FormatInt(n, 10)
			}
			k := execKey{e.SandboxID, e.ToolCallID}
			execSpans[k] = sp
			execOrder = append(execOrder, k)

		case events.ExecEnd:
			sp, ok := execSpans[execKey{e.SandboxID, e.ToolCallID}]
			if !ok {
				continue // exec.end without a matching exec.start in this event set
			}
			var data struct {
				DurationMs int64 `json:"duration_ms"`
				Exit       int   `json:"exit"`
			}
			_ = json.Unmarshal(e.Data, &data)
			if n, ok := unixNano(e.TS); ok {
				sp.EndTimeUnixNano = strconv.FormatInt(n, 10)
				sp.Completed = true
			}
			sp.Attributes = append(sp.Attributes, intAttr("sbx.exit", int64(data.Exit)), intAttr("sbx.duration_ms", data.DurationMs))

		case events.ProcessStart:
			var p struct {
				PID     int      `json:"pid"`
				PPID    int      `json:"ppid"`
				Exe     string   `json:"exe"`
				Argv    []string `json:"argv"`
				RootPid int      `json:"root_pid"`
			}
			_ = json.Unmarshal(e.Data, &p)
			pk := procKey{e.SandboxID, strconv.Itoa(p.PID)}
			argv, _ := json.Marshal(p.Argv)
			// The /proc sweep and the eBPF exec probe can both report one pid (bash
			// -c that execs straight into its command): one span, latest image name.
			if prev, ok := procSpans[pk]; ok && !prev.Completed {
				prev.Name = p.Exe
				prev.Attributes = append(prev.Attributes, strAttr("process.command_line", string(argv)))
				continue
			}
			sp := &Span{
				TraceID: traceID,
				SpanID:  spanIDFrom(e.SandboxID + ":" + strconv.Itoa(p.PID) + ":" + e.TS),
				Name:    p.Exe,
				Kind:    KindInternal,
				Attributes: []KeyValue{
					strAttr("session.id", piSession),
					strAttr("sbx.sandbox_id", e.SandboxID),
					intAttr("process.pid", int64(p.PID)),
					intAttr("process.parent_pid", int64(p.PPID)),
					strAttr("process.command_line", string(argv)),
				},
			}
			if n, ok := unixNano(e.TS); ok {
				sp.StartTimeUnixNano = strconv.FormatInt(n, 10)
			}
			procSpans[pk] = sp
			procOrder = append(procOrder, pk)

			rk := [2]string{e.SandboxID, strconv.Itoa(p.RootPid)}
			tool := e.ToolCallID
			if tool != "" {
				rootPidToTool[rk] = tool
			} else if t, ok := rootPidToTool[rk]; ok {
				tool = t
			}
			procParentTool[pk] = tool

		case events.ProcessExit:
			var p struct {
				PID  int `json:"pid"`
				Exit int `json:"exit"`
			}
			_ = json.Unmarshal(e.Data, &p)
			pk := procKey{e.SandboxID, strconv.Itoa(p.PID)}
			if sp, ok := procSpans[pk]; ok {
				if n, ok := unixNano(e.TS); ok {
					sp.EndTimeUnixNano = strconv.FormatInt(n, 10)
					sp.Completed = true
				}
				sp.Attributes = append(sp.Attributes, intAttr("sbx.exit", int64(p.Exit)))
			}

		case events.FileAccess, events.NetConnect, events.EgressAllow, events.EgressDeny, events.SecurityAlert,
			events.SandboxStopped, events.SandboxStarted, events.SandboxPaused, events.SandboxResumed, events.SandboxArchived,
			events.SnapshotBuilding, events.SnapshotReady, events.SnapshotError, events.PreviewCreated:
			// v3 lifecycle/snapshot/preview events carry no tool_call_id of their own, so
			// findTargetSpan attaches them to the synthetic session root: plain entries on
			// the timeline, same treatment as any other type-not-in-the-switch event would
			// get if it *did* reach here (unknown types below this switch stay ignored).
			spanEvents = append(spanEvents, e)

		case events.FileRead, events.FileWrite, events.FileEdit, events.BrowserNavigate:
			if e.ToolCallID == "" {
				spanEvents = append(spanEvents, e) // no tool call to attach to; -> session root
				continue
			}
			k := execKey{e.SandboxID, e.ToolCallID}
			if _, seen := fsEvents[k]; !seen {
				fsOrder = append(fsOrder, k)
			}
			fsEvents[k] = append(fsEvents[k], e)
		}
	}

	for _, pk := range procOrder {
		tool := procParentTool[pk]
		if tool == "" {
			continue
		}
		if parent, ok := execSpans[execKey{pk.sandbox, tool}]; ok {
			procSpans[pk].ParentSpanID = parent.SpanID
		}
	}

	// Tool calls whose only events were fs/browser (no exec.start for that tool_call_id):
	// one span, named after the last event in the group, spanning first..last ts.
	for _, k := range fsOrder {
		if _, hasExec := execSpans[k]; hasExec {
			continue // an exec already covers this tool call; fs events attach to it below
		}
		group := fsEvents[k]
		first, _ := unixNano(group[0].TS)
		last, _ := unixNano(group[len(group)-1].TS)
		if last <= first {
			last = first + int64(time.Millisecond)
		}
		fsSpans[k] = &Span{
			TraceID: traceID,
			SpanID:  spanIDFrom(k.tool),
			Name:    fsSpanName(group[len(group)-1].Type),
			Kind:    KindInternal,
			Attributes: []KeyValue{
				strAttr("session.id", piSession),
				strAttr("sbx.sandbox_id", k.sandbox),
			},
			StartTimeUnixNano: strconv.FormatInt(first, 10),
			EndTimeUnixNano:   strconv.FormatInt(last, 10),
			Completed:         true,
		}
	}

	// The fs/browser events themselves become span events on their own new span (or, if an
	// exec already exists for that tool_call_id, on that exec span).
	for _, k := range fsOrder {
		target := execSpans[k]
		if target == nil {
			target = fsSpans[k]
		}
		for _, e := range fsEvents[k] {
			target.Events = append(target.Events, spanEventFrom(e))
		}
	}

	// Synthetic session root: always present, spans the whole event set.
	root := &Span{
		TraceID: traceID,
		SpanID:  spanIDFrom("session:" + piSession),
		Name:    sessionRootSpanName,
		Kind:    KindInternal,
		Attributes: []KeyValue{
			strAttr("session.id", piSession),
		},
	}
	if n, ok := unixNano(minTS); ok {
		root.StartTimeUnixNano = strconv.FormatInt(n, 10)
	}
	if n, ok := unixNano(maxTS); ok {
		root.EndTimeUnixNano = strconv.FormatInt(n, 10)
		root.Completed = true
	}

	for _, e := range spanEvents {
		target := findTargetSpan(execSpans, fsSpans, root, e)
		target.Events = append(target.Events, spanEventFrom(e))
	}

	out := make([]Span, 0, len(execOrder)+len(fsOrder)+len(procOrder)+1)
	out = append(out, *root)
	for _, k := range execOrder {
		out = append(out, *execSpans[k])
	}
	for _, k := range fsOrder {
		if sp, ok := fsSpans[k]; ok {
			out = append(out, *sp)
		}
	}
	for _, k := range procOrder {
		sp := procSpans[k]
		// A process whose exit was never observed (the 25 ms sweep missed it, or
		// it is still running) ends where the session does; marked not completed
		// so the OTLP pusher leaves it open.
		if sp.EndTimeUnixNano == "" {
			sp.EndTimeUnixNano = root.EndTimeUnixNano
		}
		out = append(out, *sp)
	}
	return out
}

func spanEventFrom(e events.Event) SpanEvent {
	attrs := []KeyValue{}
	if e.Type == events.SecurityAlert {
		var ad events.AlertData
		_ = json.Unmarshal(e.Data, &ad)
		attrs = append(attrs, strAttr("sbx.alert.rule", ad.Rule), strAttr("sbx.alert.severity", ad.Severity))
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(e.Data, &raw)
	for k, v := range raw {
		var s string
		if json.Unmarshal(v, &s) == nil {
			attrs = append(attrs, strAttr("sbx."+k, s))
		}
	}
	n, _ := unixNano(e.TS)
	return SpanEvent{TimeUnixNano: strconv.FormatInt(n, 10), Name: e.Type, Attributes: attrs}
}

// findTargetSpan attributes a span event to the matching exec or fs/browser span by
// tool_call_id, falling back to the synthetic session root when tool_call_id is empty or
// doesn't match any known span (protocol.md §1.2).
func findTargetSpan(execSpans map[execKey]*Span, fsSpans map[execKey]*Span, root *Span, e events.Event) *Span {
	if e.ToolCallID != "" {
		k := execKey{e.SandboxID, e.ToolCallID}
		if sp, ok := execSpans[k]; ok {
			return sp
		}
		if sp, ok := fsSpans[k]; ok {
			return sp
		}
	}
	return root
}

func sortByTS(evs []events.Event) {
	slices.SortStableFunc(evs, func(a, b events.Event) int { return strings.Compare(a.TS, b.TS) })
}

// Build wraps BuildSpans into a full OTLP/JSON ExportTraceServiceRequest.
func Build(piSession string, evs []events.Event) *ExportTraceServiceRequest {
	return &ExportTraceServiceRequest{
		ResourceSpans: []ResourceSpans{{
			Resource: Resource{Attributes: []KeyValue{strAttr("service.name", "sandbox")}},
			ScopeSpans: []ScopeSpans{{
				Scope: scopeSpansScope{Name: "sandbox-controlplane"},
				Spans: BuildSpans(piSession, evs),
			}},
		}},
	}
}
