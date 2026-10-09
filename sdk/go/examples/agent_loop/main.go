// A ~40-line agent loop: a fake "model" emits tool calls, we execute them in the
// sandbox, and feed the result back. Swap fakeModelStep for a real LLM call to make
// it real (the API key stays on the host; only the tool call crosses into the sandbox).
//
//	SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev go run ./examples/agent_loop
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	qafas "github.com/exitCodeNihil/qafas-sandbox/sdk/go"
)

type toolCall struct{ Tool, Command string }

// A tiny scripted "plan" standing in for real model output, one tool call per step.
var plan = []toolCall{
	{"bash", "echo 'agent says hi' && pwd"},
	{"bash", "ls | head -5"},
}

// fakeModelStep stands in for an LLM call: the next tool call, or nil when done.
func fakeModelStep(step int, lastResult string) *toolCall {
	if step >= len(plan) {
		return nil
	}
	return &plan[step]
}

func runToolCall(ctx context.Context, sb *qafas.Sandbox, call *toolCall) (string, error) {
	if call.Tool != "bash" {
		return "", fmt.Errorf("unknown tool: %s", call.Tool)
	}
	// Stream output as it arrives; the result also carries it in full.
	res, err := sb.Exec(ctx, call.Command, &qafas.ExecOptions{ToolCallID: "call_" + call.Tool})
	if err != nil {
		return "", err
	}
	return res.Stdout + res.Stderr, nil
}

func main() {
	ctx := context.Background()
	cwd, _ := os.Getwd()
	sb, err := qafas.Acquire(ctx, os.Getenv("SANDBOX_URL"), cwd, "sdk-go-agent-loop", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer sb.Destroy(ctx)
	fmt.Printf("sandbox %s ready, workspace=%s\n\n", sb.ID, sb.WorkspacePath)

	last := ""
	for step := 0; ; step++ {
		call := fakeModelStep(step, last)
		if call == nil {
			break
		}
		fmt.Printf("[model] tool call: %+v\n", *call)
		if last, err = runToolCall(ctx, sb, call); err != nil {
			sb.Destroy(ctx)
			log.Fatal(err)
		}
		fmt.Printf("[sandbox output]\n%s\n", last)
	}
	fmt.Println("agent loop finished")
}
