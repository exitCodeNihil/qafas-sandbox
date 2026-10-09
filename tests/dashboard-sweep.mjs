// Opens every dashboard page for every session and sandbox in the control plane and fails on any
// uncaught page error. Usage: SBX_ADMIN_TOKEN=admin node tests/dashboard-sweep.mjs [http://127.0.0.1:7800]
// Needs bench/node_modules (playwright-core) and a Chrome: SBX_CHROME=/path/to/chrome overrides the default.
import { chromium } from "../bench/node_modules/playwright-core/index.mjs";
const base = process.argv[2] ?? "http://127.0.0.1:7800";
const TOKEN = process.env.SBX_ADMIN_TOKEN ?? "admin";
// Every row renders the same components, so the crawl visits only the newest ones
// (SBX_SWEEP_RECENT, default 40 each): destroyed rows accumulate across runs and each
// page costs ~1 s, which made a full crawl grow past 30 min.
const RECENT = Number(process.env.SBX_SWEEP_RECENT ?? 40);
const recent = (rows, key) => (Array.isArray(rows) ? rows : []).sort((a, b) => String(b[key]).localeCompare(String(a[key]))).slice(0, RECENT);
const sessions = recent(await (await fetch(base + "/api/sessions", { headers: { Authorization: "Bearer " + TOKEN } })).json(), "last_ts");
const sandboxes = recent(await (await fetch(base + "/api/sandboxes", { headers: { Authorization: "Bearer " + TOKEN } })).json(), "created_at");
const sweepCleanups = [];
const b = await chromium.launch({ executablePath: process.env.SBX_CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" }); const ctx = await b.newContext(); const page = await ctx.newPage();
await page.goto(base + "/overview"); await page.evaluate((t) => localStorage.setItem("sbx_admin_token", t), TOKEN);
const bad = []; let n = 0; let cur = "";
page.on("pageerror", (e) => bad.push(cur + ": " + String(e.message).slice(0, 100)));
const keys = await (await fetch(base + "/api/keys", { headers: { Authorization: "Bearer " + TOKEN } })).json().catch(() => []);
const urls = ["/overview", "/sessions", "/alerts", "/sandboxes", "/snapshots", "/templates", "/keys", "/hosts", "/egress", "/policy", "/settings/observability", "/get-started"];
for (const s of sessions) for (const t of ["", "?tab=trace", "?tab=processes", "?tab=files", "?tab=network", "?tab=alerts"]) urls.push("/sessions/" + encodeURIComponent(s.pi_session) + t);
for (const sb of sandboxes) for (const t of ["", "?tab=preview", "?tab=processes", "?tab=events", "?tab=sessions"]) urls.push("/sandboxes/" + sb.id + t);
for (const k of Array.isArray(keys) ? keys : []) urls.push("/keys/" + k.id);
for (const u of urls) { cur = u; await page.goto(base + u, { waitUntil: "networkidle" }).catch((e) => bad.push(u + ": nav " + e.message.slice(0, 60))); n++; }

// Drawer scenario: the Create Sandbox runtime picker matches the fleet's advertised tiers
// (docs/decisions.md D25 — Firecracker/Docker/Process, only what the live hosts serve),
// "base" is offered as a template, an inline field error surfaces client-side, the
// Template/Dockerfile switch reveals a textarea, an empty workspace with a valid name
// never surfaces a workspace error (v4c D26 — workspace is optional everywhere), and the
// Create Template drawer states which runtime a build applies to.
cur = "create-sandbox-drawer";
const RUNTIME_LABELS = { remote: "Firecracker microVM", vm: "Docker container", native: "Process" };
try {
  const hosts = await (await fetch(base + "/api/hosts", { headers: { Authorization: "Bearer " + TOKEN } })).json().catch(() => []);
  const fleetTiers = new Set((Array.isArray(hosts) ? hosts : []).flatMap((h) => h.tiers ?? []));
  const expectedRuntimes = ["remote", "vm", "native"].filter((t) => fleetTiers.has(t));

  await page.goto(base + "/sandboxes", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Create Sandbox" }).first().click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("heading", { name: "Create Sandbox" }).waitFor();
  // The runtime controls render once /api/hosts has answered.
  if (expectedRuntimes.length > 1) await dialog.getByRole("radio").first().waitFor({ timeout: 10000 }).catch(() => {});

  if (expectedRuntimes.length === 1) {
    const only = RUNTIME_LABELS[expectedRuntimes[0]];
    if (!(await dialog.getByText(`Runtime: ${only} (the only runtime in this fleet)`).count()))
      bad.push(cur + ": expected the single-runtime read-only line for " + only);
  } else if (expectedRuntimes.length > 1) {
    for (const t of expectedRuntimes) {
      // The runtime radios render once /api/hosts answers; wait for each by name.
      const ok = await dialog.getByRole("radio", { name: RUNTIME_LABELS[t] }).first().waitFor({ timeout: 10000 }).then(() => true, () => false);
      if (!ok) bad.push(cur + ": missing runtime option " + RUNTIME_LABELS[t]);
    }
  } else {
    bad.push(cur + ": fleet reports no runtimes");
  }

  // Process runtime shows a read-only "base" line instead of the Template selector.
  const runtimeIsProcessOnly = expectedRuntimes.length === 1 && expectedRuntimes[0] === "native";
  if (!runtimeIsProcessOnly) {
    const templateCombo = dialog.getByRole("combobox", { name: "Template" });
    await templateCombo.click();
    const templateOptions = (await page.getByRole("option").allTextContents()).join(" | ");
    await templateCombo.click(); // toggle the listbox closed again (not Escape — that would close the drawer)
    if (!templateOptions.includes("base")) bad.push(cur + ": template list missing base (" + templateOptions + ")");

    // The Template/Dockerfile switch reveals a Dockerfile textarea.
    await dialog.getByRole("radio", { name: "Dockerfile", exact: true }).click();
    if (!(await dialog.getByLabel("Dockerfile", { exact: false }).count())) bad.push(cur + ": Dockerfile switch did not show a textarea");
    await dialog.getByRole("radio", { name: "Existing template", exact: true }).click();
  }

  // TextInput appends a " ∙ Optional"/" ∙ Required" badge to its <label>, so match by substring.
  await dialog.getByLabel("Name", { exact: false }).fill("Bad Name!");
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  if (!(await dialog.locator("text=/Lowercase letters, digits/").count())) bad.push(cur + ": no inline error for an invalid name");

  // Workspace is optional everywhere (v4c D26): a valid name with an empty workspace
  // must never surface a workspace-required error.
  const wsName = "sweep-ws-" + Date.now().toString(36);
  await dialog.getByLabel("Name", { exact: false }).fill(wsName);
  await dialog.getByRole("button", { name: "Create", exact: true }).click();
  await page.waitForTimeout(300);
  // Whatever happens next, a sandbox the sweep created must not outlive the sweep.
  const cleanupWs = async () => {
    const all = await (await fetch(base + "/api/sandboxes", { headers: { Authorization: "Bearer " + TOKEN } })).json();
    for (const sb of all.filter((x) => x.name === wsName && x.state !== "destroyed"))
      await fetch(base + "/api/sandboxes/" + sb.id, { method: "DELETE", headers: { Authorization: "Bearer " + TOKEN } });
  };
  sweepCleanups.push(cleanupWs);
  if (await dialog.count()) {
    if (await dialog.locator("text=/[Ww]orkspace.*[Rr]equired|Required.*absolute path/").count())
      bad.push(cur + ": workspace shown as required with an empty value");
    const cancelBtn = dialog.getByRole("button", { name: "Cancel" });
    if (await cancelBtn.count()) await cancelBtn.click();
  }
} catch (e) {
  bad.push(cur + ": " + String(e.message).slice(0, 150));
}

// Duplicate name (N4): submitting a name that already belongs to a live sandbox, with
// the Dockerfile source selected, must show the inline "already named" error under
// Name immediately — never after paying for a (~100s) template build first. A
// throwaway fixture sandbox supplies the collision; it is deleted again afterwards.
// Skips cleanly when the fleet has no template-capable runtime (Process-only).
cur = "create-sandbox-duplicate-name";
try {
  const hosts2 = await (await fetch(base + "/api/hosts", { headers: { Authorization: "Bearer " + TOKEN } })).json().catch(() => []);
  const tiers2 = new Set((Array.isArray(hosts2) ? hosts2 : []).flatMap((h) => h.tiers ?? []));
  const tplTier = ["remote", "vm"].find((t) => tiers2.has(t));
  if (!tplTier) {
    console.log(cur + ": skipped (fleet has no template-capable runtime)");
  } else {
    const dupName = "sweep-dup-" + Date.now().toString(36);
    const fixtureRes = await fetch(base + "/api/sandboxes", {
      method: "POST",
      headers: { Authorization: "Bearer " + TOKEN, "Content-Type": "application/json" },
      body: JSON.stringify({ name: dupName, isolation: tplTier }),
    });
    const fixture = await fixtureRes.json();
    if (!fixtureRes.ok || !fixture.id) throw new Error("fixture create failed: " + JSON.stringify(fixture));
    try {
      await page.goto(base + "/sandboxes", { waitUntil: "networkidle" });
      await page.getByRole("button", { name: "Create Sandbox" }).first().click();
      const dupDialog = page.getByRole("dialog");
      await dupDialog.getByRole("heading", { name: "Create Sandbox" }).waitFor();
      const radio = dupDialog.getByRole("radio", { name: RUNTIME_LABELS[tplTier] });
      if (await radio.count()) await radio.click(); // force the runtime that owns dupName
      const dockerfileRadio = dupDialog.getByRole("radio", { name: "Dockerfile", exact: true });
      if (await dockerfileRadio.count()) await dockerfileRadio.click();
      await dupDialog.getByLabel("Name", { exact: false }).fill(dupName);
      const t0 = Date.now();
      await dupDialog.getByRole("button", { name: "Create", exact: true }).click();
      await dupDialog.locator("text=/already named/").waitFor({ timeout: 8000 }).catch(() => {});
      const elapsedMs = Date.now() - t0;
      if (!(await dupDialog.locator("text=/already named/").count())) bad.push(cur + ": no inline duplicate-name error");
      if (elapsedMs > 15000) bad.push(cur + ": rejection took " + elapsedMs + "ms — looks like a template got built first");
      const cancelBtn = dupDialog.getByRole("button", { name: "Cancel" });
      if (await cancelBtn.count()) await cancelBtn.click();
    } finally {
      await fetch(base + "/api/sandboxes/" + fixture.id, { method: "DELETE", headers: { Authorization: "Bearer " + TOKEN } }).catch(() => {});
    }
  }
} catch (e) {
  bad.push(cur + ": " + String(e.message).slice(0, 150));
}

cur = "create-snapshot-drawer";
try {
  await page.goto(base + "/snapshots", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Create Template" }).first().click();
  const dialog2 = page.getByRole("dialog");
  await dialog2.getByRole("heading", { name: "Create Template" }).waitFor();
  await dialog2.locator(".sbx-field-help").first().waitFor({ timeout: 10000 }).catch(() => {});
  await page.waitForTimeout(500);
  // One of the per-runtime help lines (Firecracker memory capture, Docker image,
  // checkpoint) or the no-runtime notice must be on screen.
  const helpTexts = await dialog2.locator(".sbx-field-help, [role=alert], .sbx-notice").allInnerTexts();
  const hasHelp = helpTexts.some((t) => /captures memory|podman image|Captures memory and disk|can build templates/i.test(t));
  if (!hasHelp) bad.push(cur + ": missing the runtime-applicability help line; saw: " + helpTexts.join(" | ").slice(0, 200));
  await dialog2.getByRole("button", { name: "Cancel" }).click();
} catch (e) {
  bad.push(cur + ": " + String(e.message).slice(0, 150));
}

// Warm editor (v4): the Snapshots table's inline "Keep warm" number, PUT on blur — set
// it to the value it already shows (so the daemon fan-out never has to change anything)
// and expect no error toast (role="alert"). Skips cleanly when the fleet has no snapshots.
cur = "snapshots-warm-editor";
try {
  await page.goto(base + "/snapshots", { waitUntil: "networkidle" });
  const warmInput = page.getByRole("spinbutton", { name: /^Keep warm for /i }).first();
  if (await warmInput.count()) {
    const current = await warmInput.inputValue();
    await warmInput.click();
    await warmInput.fill(current);
    await warmInput.blur();
    await page.waitForTimeout(300);
    // The toast live region is always present and empty; only text means a toast fired.
    if ((await page.getByRole("alert").allInnerTexts()).some((t) => t.trim())) bad.push(cur + ": unexpected error toast setting warm to its current value");
  }
} catch (e) {
  bad.push(cur + ": " + String(e.message).slice(0, 150));
}

// Run command panel (sandbox detail): creates nothing. When a live sandbox already
// exists, run `echo ok` from its page and expect the rendered stdout to contain "ok" —
// exercises POST /api/sandboxes/{id}/exec end to end. Skips cleanly with no live sandbox.
cur = "sandbox-run-command";
try {
  const live = sandboxes.find((sb) => sb.state !== "destroyed");
  if (live) {
    await page.goto(base + "/sandboxes/" + live.id, { waitUntil: "networkidle" });
    const cmdInput = page.getByRole("textbox", { name: "Command", exact: true });
    if (await cmdInput.count()) {
      await cmdInput.fill("echo ok");
      await page.getByRole("button", { name: "Run", exact: true }).click();
      await page.waitForTimeout(1500);
      const stdoutText = (await page.locator(".sbx-code pre").allInnerTexts()).join("\n");
      if (!stdoutText.includes("ok")) bad.push(cur + ": expected stdout to contain 'ok', got: " + stdoutText.slice(0, 120));
    } else {
      bad.push(cur + ": Run command input not found on a live sandbox's page (state " + live.state + ")");
    }
  }
} catch (e) {
  bad.push(cur + ": " + String(e.message).slice(0, 150));
}

console.log("visited", n, "pages;", sessions.length, "sessions,", sandboxes.length, "sandboxes; errors:", bad.length ? "\n" + bad.join("\n") : "none");
for (const fn of sweepCleanups) await fn().catch(() => {});
await b.close();
process.exit(bad.length ? 1 : 0);
