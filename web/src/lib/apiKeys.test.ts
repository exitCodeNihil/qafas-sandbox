// Run: node --test src/lib/apiKeys.test.ts
// The control plane's /api/keys routes don't exist yet (cp-keys work in
// progress) so there's nothing live to hit against; this covers the one
// non-trivial bit of logic added on the web side — the limits summary
// formatter — directly, instead of standing up a fake backend.
import { test } from "node:test";
import assert from "node:assert/strict";
import { limitsSummary, keyPrefixLabel, sinceIso } from "./apiKeys.ts";

test("keyPrefixLabel: adds the sbx_ literal and hides the secret", () => {
  // ApiKey.prefix from the live control plane is just the 8 random chars,
  // no "sbx_" — confirmed against GET /api/keys on 127.0.0.1:7800.
  assert.equal(keyPrefixLabel("avvvku7i"), "sbx_avvvku7i_…");
});

test("limitsSummary: no fields set reads unlimited", () => {
  assert.equal(limitsSummary({}), "unlimited");
  assert.equal(limitsSummary(undefined), "unlimited");
  assert.equal(limitsSummary(null), "unlimited");
});

test("limitsSummary: composes set fields in the documented order", () => {
  assert.equal(
    limitsSummary({ max_concurrent: 5, max_per_hour: 60, allowed_tiers: ["vm", "remote"], max_ttl_secs: 7200 }),
    "max 5 live · 60/h · Docker,Firecracker · ttl 2h",
  );
});

test("limitsSummary: partial limits omit the unset fields", () => {
  assert.equal(limitsSummary({ max_concurrent: 3 }), "max 3 live");
  assert.equal(limitsSummary({ allowed_tiers: ["native"] }), "Process");
});

test("limitsSummary: ttl falls back to minutes then seconds", () => {
  assert.equal(limitsSummary({ max_ttl_secs: 90 * 60 }), "ttl 90m");
  assert.equal(limitsSummary({ max_ttl_secs: 45 }), "ttl 45s");
});

test("sinceIso: 24h is ~24 hours before now", () => {
  const ms = Date.now() - new Date(sinceIso("24h")).getTime();
  assert.ok(Math.abs(ms - 24 * 3600_000) < 5000, `expected ~24h, got ${ms}ms`);
});
