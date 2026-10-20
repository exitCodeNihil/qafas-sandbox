// The remote tier's in-guest feed (bpftrace, D19) must be live in every sandbox it hands out.
// Creates N remote sandboxes one after another; each reads a canary as its first command, and the
// sandbox counts only if the alerts only bpftrace can raise arrive: the child's argv (`process.start`
// off the exec tracepoint) and the file open (`evidence.source: "bpftrace"`). The command-line alert
// comes from the exec request itself and is reported but proves nothing about the feed.
// Usage: node tests/remote-feed.mjs <qafas_url> <admin_token> [sandboxes=10] [delay_ms=0]
// Exit 1 unless every sandbox shows both bpftrace alerts. Needs Node 22+ (global WebSocket).
const [url, token, count = "10", delay = "0"] = process.argv.slice(2);
const H = { Authorization: `Bearer ${token}`, "content-type": "application/json" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const alerts = new Map(); // sandbox id -> canary.read alerts
const cats = new Map(); // sandbox id -> argv of the `cat` process.start (how /proc described it)
const ws = new WebSocket(`${url.replace(/^http/, "ws")}/events/ws`, { headers: { Authorization: `Bearer ${token}` } });
ws.onmessage = (m) => {
  try {
    const e = JSON.parse(m.data);
    if (e.type === "security.alert" && e.data.rule === "canary.read" && alerts.has(e.sandbox_id)) alerts.get(e.sandbox_id).push(e.data);
    if (e.type === "process.start" && /\/cat$/.test(e.data.exe) && alerts.has(e.sandbox_id)) cats.set(e.sandbox_id, e.data.argv);
  } catch {}
};
await new Promise((res, rej) => ((ws.onopen = res), (ws.onerror = rej)));
const kind = (d) => (d.evidence?.source === "bpftrace" ? "open" : d.evidence?.argv ? "argv" : d.evidence?.cmd ? "cmd" : d.source ?? "other");
const rows = [];
for (let i = 0; i < Number(count); i++) {
  const asked = Date.now();
  const r = await fetch(`${url}/sandboxes`, { method: "POST", headers: H, body: JSON.stringify({ template: "base", isolation: "remote", pi_session: "remote-feed" }) });
  if (!r.ok) { console.error("create failed", r.status, await r.text()); process.exit(2); }
  const sb = await r.json();
  alerts.set(sb.id, []);
  const createMs = Date.now() - asked;
  await sleep(Number(delay));
  const x = await fetch(`${sb.endpoint}/exec`, {
    method: "POST",
    headers: { Authorization: `Bearer ${sb.token}`, "content-type": "application/json", "X-Pi-Session": "remote-feed", "X-Tool-Call-Id": `feed-${i}` },
    body: JSON.stringify({ cmd: "cat ~/.aws/credentials >/dev/null; echo done", timeout_ms: 30000 }),
  });
  const out = x.ok ? (await x.json()).stdout.trim() : `http ${x.status}`;
  await sleep(2000);
  const kinds = alerts.get(sb.id).map(kind);
  const n = (k) => kinds.filter((x) => x === k).length;
  rows.push({ sandbox: sb.id, pooled: Date.parse(sb.info.created_at) < asked, create_ms: createMs, out, cmd: n("cmd"), argv: n("argv"), open: n("open"), cat_argv: JSON.stringify(cats.get(sb.id) ?? "-"), other: kinds.filter((k) => !["cmd", "argv", "open"].includes(k)).join(",") || "-" });
  await fetch(`${url}/sandboxes/${sb.id}`, { method: "DELETE", headers: H });
}
ws.close();
console.table(rows);
const fed = rows.filter((r) => r.argv > 0 && r.open > 0).length;
console.log(`${fed === rows.length ? "ALL FED" : "FAIL"}: bpftrace alerts (argv and open) in ${fed}/${rows.length} sandboxes`);
process.exit(fed === rows.length ? 0 : 1);
