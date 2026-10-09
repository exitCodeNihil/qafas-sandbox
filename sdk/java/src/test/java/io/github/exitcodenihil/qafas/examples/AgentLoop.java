package io.github.exitcodenihil.qafas.examples;

import io.github.exitcodenihil.qafas.ExecResult;
import io.github.exitcodenihil.qafas.Sandbox;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Small agent loop: a fake "model" emits tool calls, we execute them in the sandbox and feed the result back.
 * Swap {@link #fakeModelStep} for a real LLM call to make it real.
 */
public final class AgentLoop {
    /** A tiny scripted plan standing in for real model output: each step is one tool call, in order. */
    private static final List<Map<String, String>> PLAN = List.of(
            Map.of("tool", "bash", "command", "echo 'agent says hi' && pwd"),
            Map.of("tool", "bash", "command", "ls | head -5"));

    /** Stand-in for an LLM call: the next tool call, or null when done. */
    static Map<String, String> fakeModelStep(int stepIndex, String lastResult) {
        return stepIndex >= PLAN.size() ? null : PLAN.get(stepIndex);
    }

    static String runToolCall(Sandbox sb, Map<String, String> call) throws IOException {
        if (call.get("tool").equals("bash")) {
            ExecResult r = sb.execBuffered(call.get("command"));
            return r.stdout() + r.stderr();
        }
        throw new IllegalArgumentException("unknown tool: " + call.get("tool"));
    }

    public static void main(String[] args) throws Exception {
        try (Sandbox sb = Sandbox.create(System.getenv("SANDBOX_URL"), null, "sdk-java-agent-loop")) {
            System.out.printf("sandbox %s ready, workspace=%s%n%n", sb.id(), sb.workspacePath());
            String last = null;
            for (int step = 0; ; step++) {
                Map<String, String> call = fakeModelStep(step, last);
                if (call == null) break;
                System.out.println("[model] tool call: " + call);
                last = runToolCall(sb, call);
                System.out.println("[sandbox output]\n" + last);
            }
            System.out.println("agent loop finished");
        }
    }
}
