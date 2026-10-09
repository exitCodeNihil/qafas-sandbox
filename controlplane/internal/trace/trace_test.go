package trace

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/exitCodeNihil/qafas-sandbox/controlplane/internal/events"
)

func ev(id, ts, sandbox, toolCall, typ string, data any) events.Event {
	b, _ := json.Marshal(data)
	return events.Event{ID: id, TS: ts, SandboxID: sandbox, PiSession: "sess1", ToolCallID: toolCall, Type: typ, Data: b}
}

func TestBuildSpansExecAndProcessChildren(t *testing.T) {
	evs := []events.Event{
		ev("01A", "2026-09-08T10:00:00.000Z", "sbx1", "tool1", events.ExecStart, map[string]string{"cmd": "npm ci", "cwd": "/repo"}),
		ev("01B", "2026-09-08T10:00:00.010Z", "sbx1", "tool1", events.ProcessStart, map[string]any{"pid": 100, "ppid": 1, "exe": "npm", "argv": []string{"npm", "ci"}, "root_pid": 100}),
		ev("01C", "2026-09-08T10:00:00.020Z", "sbx1", "", events.ProcessStart, map[string]any{"pid": 101, "ppid": 100, "exe": "node", "argv": []string{"node"}, "root_pid": 100}),
		ev("01D", "2026-09-08T10:00:00.030Z", "sbx1", "tool1", events.FileAccess, map[string]any{"pid": 101, "path": "/repo/package.json", "op": "read", "sensitive": false}),
		ev("01E", "2026-09-08T10:00:00.900Z", "sbx1", "", events.ProcessExit, map[string]any{"pid": 101, "exit": 0}),
		ev("01F", "2026-09-08T10:00:01.000Z", "sbx1", "tool1", events.ProcessExit, map[string]any{"pid": 100, "exit": 0}),
		ev("01G", "2026-09-08T10:00:01.100Z", "sbx1", "tool1", events.ExecEnd, map[string]any{"exit": 0, "duration_ms": 1100}),
	}

	spans := BuildSpans("sess1", evs)
	if len(spans) != 4 {
		t.Fatalf("want 4 spans (session root + 1 exec + 2 process), got %d", len(spans))
	}
	var foundRoot bool
	for _, sp := range spans {
		if sp.Name == sessionRootSpanName {
			foundRoot = true
		}
	}
	if !foundRoot {
		t.Fatal("synthetic session root span not found")
	}

	pidOf := func(sp Span) (int, bool) {
		for _, a := range sp.Attributes {
			if a.Key == "process.pid" && a.Value.IntValue != nil {
				n, err := strconv.Atoi(*a.Value.IntValue)
				return n, err == nil
			}
		}
		return 0, false
	}

	var execSpan, npmSpan, nodeSpan *Span
	for i := range spans {
		pid, isProcess := pidOf(spans[i])
		switch {
		case spans[i].Name == "npm" && !isProcess:
			execSpan = &spans[i]
		case pid == 100:
			npmSpan = &spans[i]
		case pid == 101:
			nodeSpan = &spans[i]
		}
	}

	if execSpan == nil {
		t.Fatal("exec span not found")
	}
	if !execSpan.Completed {
		t.Fatal("exec span should be completed (has exec.start and exec.end)")
	}
	if execSpan.TraceID != TraceID("sess1") {
		t.Fatalf("trace id mismatch: %svs%s", execSpan.TraceID, TraceID("sess1"))
	}
	if len(execSpan.Events) != 1 || execSpan.Events[0].Name != events.FileAccess {
		t.Fatalf("want 1 file.access span event on the exec span, got %+v", execSpan.Events)
	}

	if npmSpan == nil {
		t.Fatal("npm process span (root_pid=100, tool_call_id set directly) not found")
	}
	if npmSpan.ParentSpanID != execSpan.SpanID {
		t.Fatalf("npm process span should be a child of the exec span: got parent=%s want=%s", npmSpan.ParentSpanID, execSpan.SpanID)
	}

	if nodeSpan == nil {
		t.Fatal("node process span (root_pid=100, tool_call_id EMPTY, attributed via root_pid) not found")
	}
	if nodeSpan.ParentSpanID != execSpan.SpanID {
		t.Fatalf("node process span should be attributed to the exec span via root_pid: got parent=%s want=%s", nodeSpan.ParentSpanID, execSpan.SpanID)
	}
	if !nodeSpan.Completed {
		t.Fatal("node process span should be completed")
	}
}

func TestBuildValidOTLPJSON(t *testing.T) {
	evs := []events.Event{
		ev("01A", "2026-09-08T10:00:00.000Z", "sbx1", "tool1", events.ExecStart, map[string]string{"cmd": "true", "cwd": "/repo"}),
		ev("01B", "2026-09-08T10:00:00.050Z", "sbx1", "tool1", events.ExecEnd, map[string]any{"exit": 0, "duration_ms": 50}),
	}
	req := Build("sess1", evs)
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	rs, ok := round["resourceSpans"].([]any)
	if !ok || len(rs) != 1 {
		t.Fatalf("resourceSpans shape: %#v", round["resourceSpans"])
	}
}

func TestUserBashGetsUniqueSpanWithoutToolCallID(t *testing.T) {
	evs := []events.Event{
		ev("01A", "2026-09-08T10:00:00.000Z", "sbx1", "", events.ExecStart, map[string]string{"cmd": "ls", "cwd": "/repo"}),
		ev("01B", "2026-09-08T10:00:00.010Z", "sbx1", "", events.ExecEnd, map[string]any{"exit": 0, "duration_ms": 10}),
	}
	spans := BuildSpans("sess1", evs)
	if len(spans) != 2 { // session root + the user_bash exec span
		t.Fatalf("want 2 spans, got %d", len(spans))
	}
	var execSpan *Span
	for i := range spans {
		if spans[i].Name != sessionRootSpanName {
			execSpan = &spans[i]
		}
	}
	if execSpan == nil || !execSpan.Completed {
		t.Fatal("user_bash span (empty tool_call_id, falls back to event id) should still pair start+end")
	}
}

func TestFsOnlyToolCallGetsOwnSpan(t *testing.T) {
	// The `read` tool never execs: just a file.read with a tool_call_id, per
	// docs/protocol.md §1.2.
	evs := []events.Event{
		ev("01A", "2026-09-08T10:00:00.000Z", "sbx1", "toolRead", events.FileRead, map[string]any{"path": "/repo/a.txt", "bytes": 100}),
	}
	spans := BuildSpans("sess1", evs)
	if len(spans) != 2 { // session root + the fs span
		t.Fatalf("want 2 spans (root + fs), got %d", len(spans))
	}
	var fsSpan *Span
	for i := range spans {
		if spans[i].Name != sessionRootSpanName {
			fsSpan = &spans[i]
		}
	}
	if fsSpan == nil {
		t.Fatal("fs-only span not found")
	}
	if fsSpan.Name != "fs.read" {
		t.Fatalf("want span name fs.read, got %q", fsSpan.Name)
	}
	if !fsSpan.Completed {
		t.Fatal("fs-only span should have both start and end (minimum 1ms)")
	}
	if len(fsSpan.Events) != 1 || fsSpan.Events[0].Name != events.FileRead {
		t.Fatalf("want the file.read event attached as a span event, got %+v", fsSpan.Events)
	}
}

func TestEmptyToolCallIDAttachesToSessionRoot(t *testing.T) {
	evs := []events.Event{
		ev("01A", "2026-09-08T10:00:00.000Z", "sbx1", "tool1", events.ExecStart, map[string]string{"cmd": "true", "cwd": "/repo"}),
		ev("01B", "2026-09-08T10:00:00.010Z", "sbx1", "tool1", events.ExecEnd, map[string]any{"exit": 0, "duration_ms": 10}),
		// A daemon-generated alert (e.g. store.CheckDenyBurst) has no tool_call_id.
		ev("01C", "2026-09-08T10:00:00.020Z", "sbx1", "", events.SecurityAlert, map[string]any{"severity": "medium", "rule": "egress.deny_burst", "msg": "5 in 10s"}),
	}
	spans := BuildSpans("sess1", evs)
	var root *Span
	for i := range spans {
		if spans[i].Name == sessionRootSpanName {
			root = &spans[i]
		}
	}
	if root == nil {
		t.Fatal("session root not found")
	}
	if len(root.Events) != 1 || root.Events[0].Name != events.SecurityAlert {
		t.Fatalf("want the empty-tool_call_id alert attached to the session root, got %+v", root.Events)
	}
}
