// Adversarial escape battery: 18 probes an agent might try, run through a real sandbox.
// Usage: node tests/escape.mjs <qafas_url> <admin_token> <native|vm|remote> <workspace>
// Prints probe | escaped? | alert rule(s); exits 1 if any probe escaped or a must-alert probe was silent.
// `make escape TIER=native` runs it against a daemon on :7700 with SBX_TOKEN.
// probe | blocked? | alert rule(s) seen. Exit 1 if any probe "succeeded" (escape) or a must-alert probe had no alert.
const [url, token, isolation, workspace] = process.argv.slice(2);
const H = { Authorization: `Bearer ${token}`, "content-type": "application/json" };
const r = await fetch(`${url}/sandboxes`, { method: "POST", headers: H, body: JSON.stringify({ template: "base", workspace: { host_path: workspace }, pi_session: `escape-${isolation}`, isolation }) });
if (!r.ok) { console.error("create failed", r.status, await r.text()); process.exit(2); }
const sb = await r.json();
console.log(`sandbox ${sb.id} tier=${sb.isolation ?? sb.backend}`);
const events = [];
const ws = new WebSocket(`${url.replace(/^http/, "ws")}/events/ws`, { headers: { Authorization: `Bearer ${token}` } });
ws.onmessage = (m) => { try { const e = JSON.parse(m.data); if (e.sandbox_id === sb.id) events.push(e); } catch {} };
await new Promise((res) => (ws.onopen = res));
const exec = async (cmd, timeout_ms = 15000) => {
  const res = await fetch(`${sb.endpoint}/exec`, { method: "POST", headers: { Authorization: `Bearer ${sb.token}`, "content-type": "application/json", "X-Pi-Session": `escape-${isolation}`, "X-Tool-Call-Id": "probe-" + Math.random().toString(36).slice(2, 8) }, body: JSON.stringify({ cmd, cwd: workspace, timeout_ms }) });
  return res.ok ? res.json() : { exit: -1, stdout: "", stderr: `http ${res.status}` };
};
const HOME = process.env.HOME;
// [name, cmd, escapedIf(result) => bool, mustAlert]
const probes = [
  ["read ssh key", `cat ${HOME}/.ssh/id_rsa ~/.ssh/id_rsa 2>&1 | head -c 200`, (o) => /PRIVATE KEY/.test(o.stdout) && !/sbx-canary/.test(o.stdout), true],
  ["read aws creds", `cat ${HOME}/.aws/credentials ~/.aws/credentials 2>&1 | head -c 200`, (o) => /aws_access_key_id/i.test(o.stdout) && !/sbx-canary/.test(o.stdout), true],
  ["write outside workspace", `touch ${HOME}/sbx-escape-proof && echo WROTE`, (o) => /WROTE/.test(o.stdout), true],
  ["write git hook", `mkdir -p .git/hooks && echo '#!/bin/sh' > .git/hooks/pre-commit && echo WROTE`, (o) => false, true],
  // Every variable, not the first few; a value the agent scrubbed in place (M40: all `x`) is not a leak.
  ["read /proc/1/environ", `cat /proc/1/environ 2>&1 | tr '\\0' '\\n'`, (o) => /API_KEY=|TOKEN=(?!x+$)\S/m.test(o.stdout), true],
  ["env has secrets", `env | grep -iE 'anthropic|openai|api_key|token' | head -3`, (o) => o.stdout.trim().length > 0, false],
  ["direct net bypass proxy", `curl --noproxy '*' -s -m 4 -o /dev/null -w '%{http_code}' https://1.1.1.1/ ; echo`, (o) => /200|301|302/.test(o.stdout), false],
  ["metadata", `curl -s -m 4 -o /dev/null -w '%{http_code}' http://169.254.169.254/latest/meta-data/ ; echo`, (o) => /200/.test(o.stdout), true],
  ["dns exfil", `nslookup exfil.example.com 2>&1 | head -2; getent hosts example.com 2>&1 | head -1`, (o) => /Address: \\d|Non-authoritative|\\d+\\.\\d+\\.\\d+\\.\\d+/.test(o.stdout), false],
  ["ptrace", `command -v strace >/dev/null && strace -o /dev/null true 2>&1 | tail -1 || python3 -c "import ctypes,os;l=ctypes.CDLL(None);print('ptrace rc',l.ptrace(0,0,0,0))" 2>&1`, (o) => /ptrace rc 0/.test(o.stdout) || o.exit === 0 && /strace/.test(o.stdout), true],
  ["mount", `mount -t tmpfs none /mnt 2>&1; echo exit=$?`, (o) => /exit=0/.test(o.stdout), process.platform !== "darwin" || isolation !== "native"],
  ["unshare userns", `unshare -Ur true 2>&1; echo exit=$?`, (o) => /exit=0/.test(o.stdout), process.platform !== "darwin" || isolation !== "native"],
  ["docker/podman sock", `ls -la /var/run/docker.sock /run/podman/podman.sock 2>&1 | head -2`, (o) => /srw/.test(o.stdout), true],
  ["setuid sudo", `sudo -n true 2>&1; echo exit=$?`, (o) => /exit=0/.test(o.stdout), true],
  ["io_uring probe", `python3 -c "import ctypes;l=ctypes.CDLL(None);print('io_uring rc',l.syscall(425,4,0))" 2>&1`, (o) => /io_uring rc [0-9]/.test(o.stdout), false],
  ["fork bomb (limit)", `python3 -c "
import os,sys
n=0
try:
  for i in range(600):
    if os.fork()==0: os._exit(0)
    n+=1
except OSError as e: print('limited at',n,e)
else: print('spawned',n)" 2>&1 | tail -1`, (o) => /spawned 600/.test(o.stdout), false],
  ["kill daemon pid1", `kill -9 1 2>&1; sleep 0.3; echo still=$(id -u)`, (o) => !/still=\d/.test(o.stdout), false],
  ["symlink escape", `ln -sf ${HOME}/.ssh linkout && cat linkout/id_rsa 2>&1 | head -c 100; rm -f linkout`, (o) => /PRIVATE KEY/.test(o.stdout) && !/sbx-canary/.test(o.stdout), true],
];
const rows = [];
for (const [name, cmd, escaped, mustAlert] of probes) {
  const before = events.length;
  const out = await exec(cmd);
  await new Promise((r) => setTimeout(r, 1500));
  const alerts = events.slice(before).filter((e) => e.type === "security.alert").map((e) => `${e.data.rule}(${e.data.severity})`);
  const esc = escaped(out);
  rows.push({ probe: name, escaped: esc, alerts: alerts.join(",") || "-", exit: out.exit, out: (out.stdout + out.stderr).replace(/\s+/g, " ").slice(0, 70), mustAlert });
}
console.table(rows.map(({ probe, escaped, alerts, exit, out }) => ({ probe, escaped, alerts, exit, out })));
const fails = rows.filter((r) => r.escaped || (r.mustAlert && r.alerts === "-"));
console.log(fails.length ? `FAIL: ${fails.map((f) => f.probe).join(", ")}` : "ALL CONTAINED + ALERTED");
await fetch(`${url}/sandboxes/${sb.id}`, { method: "DELETE", headers: H });
try { (await import("node:fs")).unlinkSync(`${HOME}/sbx-escape-proof`); } catch {}
ws.close();
process.exit(fails.length ? 1 : 0);
