#!/usr/bin/env python3
"""~40-line agent loop: a fake "model" emits tool calls, we execute them in the
sandbox, and feed the result back. Swap `fake_model_step` for a real LLM call
(e.g. anthropic.Anthropic().messages.create(..., tools=[...])) to make it real.

    SANDBOX_URL=http://127.0.0.1:7700 SBX_TOKEN=dev python3 examples/agent_loop.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qafas_sandbox import acquire  # noqa: E402

# A tiny scripted "plan" standing in for real model output: each step is one
# tool call the model wants to run, in order.
PLAN = [
    {"tool": "bash", "input": {"command": "echo 'agent says hi' && pwd"}},
    {"tool": "bash", "input": {"command": "ls | head -5"}},
]


def fake_model_step(step_index: int, last_result: str | None) -> dict | None:
    """Stand-in for an LLM call: returns the next tool call, or None when done."""
    if step_index >= len(PLAN):
        return None
    return PLAN[step_index]


def run_tool_call(sb, call: dict) -> str:
    if call["tool"] == "bash":
        result = sb.exec_buffered(call["input"]["command"])
        return result.stdout + result.stderr
    raise ValueError(f"unknown tool: {call['tool']}")


def main() -> None:
    with acquire(os.environ.get("SANDBOX_URL", "http://127.0.0.1:7700"), os.getcwd(), "sdk-python-agent-loop") as sb:
        print(f"sandbox {sb.id} ready, workspace={sb.workspace_path}\n")
        last_result, step = None, 0
        while True:
            call = fake_model_step(step, last_result)
            if call is None:
                break
            print(f"[model] tool call: {call}")
            last_result = run_tool_call(sb, call)
            print(f"[sandbox output]\n{last_result}")
            step += 1
        print("agent loop finished")


if __name__ == "__main__":
    main()
