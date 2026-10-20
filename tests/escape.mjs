// Adversarial escape battery: 21 probes an agent might try (20 on remote), run through a real sandbox.
// Usage: node tests/escape.mjs <qafas_url> <admin_token> <native|vm|remote> <workspace>
// Prints probe | escaped? | alert rule(s); exits 1 if any probe escaped or a must-alert probe was silent.
// `make escape TIER=native` runs it against a daemon on :7700 with SBX_TOKEN.
// Run it on the daemon's host, or set HOME to the home of the user the daemon serves: on native and vm the path probes use this process's HOME (on remote, the guest's own $HOME).
// probe | blocked? | alert rule(s) seen. Exit 1 if any probe "succeeded" (escape) or a must-alert probe had no alert.
import net from "node:net";
import os from "node:os";
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
// The home the path probes aim at. native and vm: this process's, as before (run it where the
// daemon serves, or set HOME). remote: a microVM shares nothing with this host, so the
// probes use the guest user's own $HOME; this process's path does not exist there, the write
// fails for want of a directory, and no alert is the result.
const HOST_HOME = process.env.HOME;
const HOME = isolation === "remote" ? (await exec(`printf %s "$HOME"`)).stdout.trim() || HOST_HOME : HOST_HOME;
// M46: Landlock restricts TCP connect by port, not by address. This host listens on its own
// non-loopback address at the sandbox's proxy port (from $HTTPS_PROXY) and at 3128, the port the
// Landlock rule allowed up to 0.3.2; a connection from the sandbox to either one is an escape.
// Skipped on macOS native, where Seatbelt allows the proxy port on localhost only.
const lan = Object.values(os.networkInterfaces()).flat().find((a) => a?.family === "IPv4" && !a.internal)?.address;
const proxyPort = Number((await exec(`printf %s "$HTTPS_PROXY"`)).stdout.match(/:(\d+)\/?$/)?.[1] ?? 0);
const seatbelt = process.platform === "darwin" && isolation === "native";
const reached = [], listening = [], servers = [];
for (const port of lan && !seatbelt ? new Set([proxyPort, 3128].filter(Boolean)) : []) {
  const srv = net.createServer((c) => { reached.push(port); c.destroy(); });
  if (await new Promise((res) => { srv.once("error", () => res(false)); srv.listen(port, lan, () => res(true)); })) {
    servers.push(srv); listening.push(port);
  }
}
const portProbe = listening.length
  ? [["proxy port on another address", listening.map((p) => `curl --noproxy '*' -s -m 4 -o /dev/null http://${lan}:${p}/; echo ${p}:$?`).join("; "), () => reached.length > 0, false]]
  : [];
if (!portProbe.length) console.log(`skipped: proxy port on another address (${seatbelt ? "macOS native: Seatbelt allows the proxy port on localhost only" : !lan ? "no non-loopback IPv4 address" : `cannot listen on ${lan}:${proxyPort} or 3128`})`);
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
  ["udp bypass proxy", `python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(4);s.sendto(b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x07example\\x03com\\x00\\x00\\x01\\x00\\x01',('1.1.1.1',53));print('UDP-ANSWER',len(s.recv(512)))" 2>&1 | tail -1`, (o) => /UDP-ANSWER/.test(o.stdout), false],
  ["tcp fast open bypass proxy", `python3 -c "import socket,signal;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);signal.alarm(5);s.sendto(b'GET / HTTP/1.0\\r\\nHost: 1.1.1.1\\r\\n\\r\\n',0x20000000,('1.1.1.1',80));print('TFO-ANSWER',len(s.recv(512)))" 2>&1 | tail -1`, (o) => /TFO-ANSWER/.test(o.stdout), false],
  ["metadata", `curl -s -m 4 -o /dev/null -w '%{http_code}' http://169.254.169.254/latest/meta-data/ ; echo`, (o) => /200/.test(o.stdout), true],
  ["dns exfil", `getent hosts example.com >/dev/null 2>&1 && echo RESOLVED-GETENT; nslookup exfil.example.com 2>&1 | grep -q '^Name:' && echo RESOLVED-NSLOOKUP; true`, (o) => /RESOLVED/.test(o.stdout), false],
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
  ...portProbe,
];
const rows = [];
// A microVM shares no filesystem with its host: a write to the guest's own (writable) home cannot
// reach the host, so "write outside workspace" has nothing to escape to there and raises no alert.
const notApplicable = isolation === "remote" ? new Set(["write outside workspace"]) : new Set();
for (const n of notApplicable) console.log(`skipped: ${n} (remote: the guest's home is its own filesystem, not the host's)`);
for (const [name, cmd, escaped, mustAlert] of probes.filter(([n]) => !notApplicable.has(n))) {
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
try { (await import("node:fs")).unlinkSync(`${HOST_HOME}/sbx-escape-proof`); } catch {}
ws.close();
for (const srv of servers) srv.close();
process.exit(fails.length ? 1 : 0);
