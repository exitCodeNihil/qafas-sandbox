// Run: node --test src/lib/format.test.ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { percentile, summarizeEvent } from "./format.ts";

test("percentile: nearest-rank on a sorted sample", () => {
  assert.equal(percentile([1, 2, 3, 4, 5], 0.95), 5);
  assert.equal(percentile([5, 4, 3, 2, 1], 0.5), 3);
  assert.equal(percentile([10], 0.95), 10);
});

test("summarizeEvent: process.exit prefers the exit code, then signal, then ended", () => {
  const base = { id: "1", ts: "", host_id: "", sandbox_id: "", pi_session: "", tool_call_id: "" } as const;
  assert.equal(summarizeEvent({ ...base, type: "process.exit", data: { exit: 0 } }), "exit 0");
  assert.equal(summarizeEvent({ ...base, type: "process.exit", data: { exit: null, signal: "SIGKILL" } }), "signal SIGKILL");
  assert.equal(summarizeEvent({ ...base, type: "process.exit", data: { exit: null } }), "ended");
});
