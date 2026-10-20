// Snapshot clones must not share randomness (remote tier). Snapshots one microVM, restores that
// snapshot N times, and from every clone collects the random part of the guest's event ULIDs,
// the canary token `POST /restored` planted, and the first 16 bytes it reads from /dev/urandom.
// Any value seen in two clones is a failure: a clone would be predictable from its siblings.
// Usage: node tests/clone-rng.mjs <qafas_url> <admin_token> [clones=5] [events_per_clone=200]
// Exit 1 on a repeat, 2 on a setup error. Needs Node 22+ (global WebSocket).
const [url, token, clones = "5", perClone = "200"] = process.argv.slice(2);
const N = Number(clones), WANT = Number(perClone);
const H = { Authorization: `Bearer ${token}`, "content-type": "application/json" };
const api = async (method, path, body) => {
  const r = await fetch(url + path, { method, headers: H, body: body && JSON.stringify(body) });
  const t = await r.text();
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${t}`);
  return t ? JSON.parse(t) : null;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Emitted by the guest agent itself; exec.* and sandbox.* come from the daemon and are not clones' state.
const GUEST = new Set(["process.start", "process.exit", "file.access", "net.connect", "sandbox.usage"]);
const seen = new Map(); // sandbox id -> guest event ids
const ws = new WebSocket(`${url.replace(/^http/, "ws")}/events/ws`, { headers: { Authorization: `Bearer ${token}` } });
ws.onmessage = (m) => {
  try {
    const e = JSON.parse(m.data);
    if (GUEST.has(e.type) && seen.has(e.sandbox_id)) seen.get(e.sandbox_id).push(e.id);
  } catch {}
};
await new Promise((res, rej) => ((ws.onopen = res), (ws.onerror = rej)));
const create = (template) => api("POST", "/sandboxes", { template, isolation: "remote", pi_session: "clone-rng" });
const exec = async (sb, cmd) => {
  const r = await fetch(`${sb.endpoint}/exec`, {
    method: "POST",
    headers: { Authorization: `Bearer ${sb.token}`, "content-type": "application/json", "X-Pi-Session": "clone-rng", "X-Tool-Call-Id": "rng" },
    body: JSON.stringify({ cmd, timeout_ms: 30000 }),
  });
  if (!r.ok) throw new Error(`exec ${r.status} ${await r.text()}`);
  return r.json();
};

const name = `rng-${Date.now().toString(36)}`;
const made = [];
let failed = false;
try {
  const src = await create("base");
  made.push(src.id);
  await exec(src, "true");
  await api("POST", "/snapshots", { name, source: { sandbox_id: src.id } });
  for (let i = 0; ; i++) {
    const s = await api("GET", `/snapshots/${name}`);
    if (s.state === "active") break;
    if (s.state === "error" || i > 180) throw new Error(`snapshot ${name}: ${s.state} ${s.error ?? ""}`);
    await sleep(1000);
  }
  console.log(`snapshot ${name} of ${src.id} is active; restoring it ${N} times`);
  await api("DELETE", `/sandboxes/${src.id}`);
  made.pop();

  const rows = [];
  for (let c = 0; c < N; c++) {
    const sb = await create(name);
    made.push(sb.id);
    seen.set(sb.id, []);
    // First thing the clone does, before anything else draws from its kernel pool.
    const urandom = (await exec(sb, "od -An -tx1 -N16 /dev/urandom | tr -d ' \\n'")).stdout.trim();
    const canary = (await exec(sb, "cat ~/.ssh/id_rsa ~/.aws/credentials")).stdout;
    const tokens = [...new Set([...canary.matchAll(/sbx-canary-.+?-([0-9A-HJKMNP-TV-Z]{26})\b/g)].map((m) => m[1]))];
    for (let k = 0; k < 40 && seen.get(sb.id).length < WANT; k++) {
      await exec(sb, "for i in $(seq 1 30); do sleep 0.05; done");
      await sleep(300);
    }
    rows.push({ clone: sb.id, events: seen.get(sb.id).length, canary: tokens.join(","), urandom });
    await api("DELETE", `/sandboxes/${sb.id}`);
    made.pop();
  }
  console.table(rows);

  // value -> set of clones it was drawn in. A ULID's last 16 characters are its 80 random bits.
  const shared = (pick) => {
    const owners = new Map();
    rows.forEach((r, i) => {
      for (const v of pick(r)) owners.set(v, (owners.get(v) ?? new Set()).add(i));
    });
    return [...owners].filter(([, s]) => s.size > 1).map(([v, s]) => `${v} in clones ${[...s].join("+")}`);
  };
  const checks = [
    ["event ULID random parts", (r) => new Set(seen.get(r.clone).map((id) => id.slice(10)))],
    ["canary token random parts", (r) => new Set(r.canary.split(",").filter(Boolean).map((u) => u.slice(10)))],
    ["first 16 bytes of /dev/urandom", (r) => new Set([r.urandom])],
  ];
  for (const r of rows) {
    if (r.events < WANT || !r.canary || r.urandom.length !== 32) {
      console.log(`FAIL: ${r.clone} gave ${r.events} events, canary "${r.canary}", urandom "${r.urandom}"`);
      failed = true;
    }
  }
  for (const [label, pick] of checks) {
    const dup = shared(pick);
    console.log(`${dup.length ? "FAIL" : "ok  "} ${label}: ${dup.length} shared across clones${dup.length ? ` (e.g. ${dup.slice(0, 3).join("; ")})` : ""}`);
    failed ||= dup.length > 0;
  }
} catch (e) {
  console.error("setup error:", e.message);
  for (const id of made) await api("DELETE", `/sandboxes/${id}`).catch(() => {});
  await api("DELETE", `/snapshots/${name}`).catch(() => {});
  ws.close();
  process.exit(2);
}
await api("DELETE", `/snapshots/${name}`).catch((e) => console.error("snapshot cleanup:", e.message));
ws.close();
console.log(failed ? "FAIL: snapshot clones share randomness" : "ALL CLONES DISTINCT");
process.exit(failed ? 1 : 0);
