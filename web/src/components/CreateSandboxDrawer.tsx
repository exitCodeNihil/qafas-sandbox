import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { TextInput } from "@astryxdesign/core/TextInput";
import { TextArea } from "@astryxdesign/core/TextArea";
import { NumberInput } from "@astryxdesign/core/NumberInput";
import { CheckboxInput } from "@astryxdesign/core/CheckboxInput";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { RadioList, RadioListItem } from "@astryxdesign/core/RadioList";
import { Selector } from "@astryxdesign/core/Selector";
import { Tokenizer } from "@astryxdesign/core/Tokenizer";
import { createStaticSource, type SearchableItem } from "@astryxdesign/core/Typeahead";
import { Button } from "@astryxdesign/core/Button";
import { Banner } from "@astryxdesign/core/Banner";
import { Drawer, DrawerSection } from "./Drawer";
import { KeyValueEditor, type KVRow } from "./KeyValueEditor";
import { CreateSnapshotDrawer } from "./CreateSnapshotDrawer";
import { Notice } from "../ui";
import { api, ApiError } from "../lib/api";
import { RUNTIMES, SIZE_NAMES, DEFAULT_SIZE, DEFAULT_SIZES, NAME_RE, NAME_RE_HELP } from "../lib/types";
import type { SnapshotInfo, Host, SandboxInfo, SizeName } from "../lib/types";
import { formatMiB } from "../lib/format";

const WORKSPACE_KEY = "sbx_last_workspace";
const TOOL_SUGGESTIONS: SearchableItem[] = ["node@22", "python@3.12", "rg", "git", "chromium"].map((t) => ({ id: t, label: t }));
const toolSource = createStaticSource(TOOL_SUGGESTIONS);
const emptySource = createStaticSource<SearchableItem>([]);

// v4c (docs/decisions.md D26): a host path is only meaningful for hosts on the same
// machine as the client, so the workspace control's help line differs per runtime and
// Firecracker hides it behind "Advanced" (files there arrive by SDK upload, not a mount).
const WORKSPACE_HELP: Record<string, string> = {
  remote: "Files are uploaded with the SDK; leave empty for an empty /home/agent.",
  vm: "A directory on the Docker host to mount at the same path. Leave empty for an empty /home/agent inside the container.",
  native: "A directory on this machine the sandbox may write. Leave empty for a scratch directory.",
};

function rowsToObject(rows: KVRow[]): Record<string, string> | undefined {
  const entries = rows.filter((r) => r.key.trim()).map((r) => [r.key.trim(), r.value] as const);
  return entries.length ? Object.fromEntries(entries) : undefined;
}

/** `GET /api/snapshots` rows, one per (host, name) — grouped for the select: one
 * option per (name, runtime), only when active somewhere. Every row — "base"
 * included — is stamped with the runtime of the host that built/serves it
 * (crates/qafas/src/snapshots.rs), so a host of one runtime never leaks into
 * another runtime's group; the picker only ever sees hosts and flags (like
 * memory-snapshot "restore") that actually apply to the chosen runtime. */
function activeSnapshotGroups(rows: SnapshotInfo[]): { name: string; kind: string; runtime?: string; hosts: string[]; memorySnapshot: boolean }[] {
  const byKey = new Map<string, { name: string; kind: string; runtime?: string; hosts: string[]; memorySnapshot: boolean }>();
  for (const s of rows) {
    if (s.state !== "active") continue;
    const key = `${s.name}::${s.runtime ?? ""}`;
    const g = byKey.get(key) ?? { name: s.name, kind: s.kind, runtime: s.runtime, hosts: [], memorySnapshot: false };
    if (s.host_id && !g.hosts.includes(s.host_id)) g.hosts.push(s.host_id);
    if (s.memory_snapshot) g.memorySnapshot = true;
    byKey.set(key, g);
  }
  return [...byKey.values()];
}

/** Where a 4xx from `POST /api/sandboxes` (or the `POST/GET /api/snapshots` calls the
 * inline Dockerfile build makes) belongs on the form (protocol.md §4, §3a):
 * 403/409 naming the tier/runtime/host is a placement failure → Runtime;
 * 404/409 naming the snapshot/template is unresolved → Snapshot;
 * a plain 400 names the field it rejected. No 404-only special string. */
function fieldForApiError(status: number, message: string): "runtime" | "snapshot" | "workspace" | "name" | "size" | null {
  const m = message.toLowerCase();
  if ((status === 403 || status === 409) && (m.includes("tier") || m.includes("runtime") || m.includes("host"))) return "runtime";
  if ((status === 404 || status === 409) && (m.includes("snapshot") || m.includes("template"))) return "snapshot";
  if (status === 400) {
    if (m.includes("workspace")) return "workspace";
    if (m.includes("name")) return "name";
    if (m.includes("tier") || m.includes("runtime") || m.includes("isolation")) return "runtime";
    if (m.includes("snapshot") || m.includes("template")) return "snapshot";
    if (m.includes("size") || m.includes("cpus") || m.includes("mem_mib") || m.includes("disk_mib")) return "size";
  }
  if (status === 403 && m.includes("may use at most")) return "size";
  if (status === 409 && (m.includes("no host has") || m.includes("cpus") || m.includes("mem_mib") || m.includes("disk_mib"))) return "size";
  return null;
}

const POLL_INTERVAL_MS = 2000;

/** Polls `GET /api/snapshots/{name}` (control plane fan-out, one row per host of that
 * runtime) until every row reports `active`, throwing on the first `error` row. Never
 * gives up on a slow build — it just keeps watching and reporting progress. Reports
 * which host is still building so the drawer can show "Building on lima-kvm… 42 s". */
async function pollTemplateActive(name: string, onProgress: (host: string, elapsedS: number) => void): Promise<void> {
  const startedAt = Date.now();
  for (;;) {
    const rows = await api.get<SnapshotInfo[]>(`/api/snapshots/${encodeURIComponent(name)}`);
    const errored = rows.find((r) => r.state === "error");
    if (errored) throw new Error(`${errored.host_id ?? "host"}: ${errored.error || "build failed"}`);
    if (rows.length > 0 && rows.every((r) => r.state === "active")) return;
    onProgress(rows.find((r) => r.state === "building")?.host_id ?? "the fleet", Math.round((Date.now() - startedAt) / 1000));
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
}

export function CreateSandboxDrawer({
  isOpen,
  onOpenChange,
  prefillSnapshot,
}: {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  prefillSnapshot?: string;
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();

  const hostsQuery = useQuery({
    queryKey: ["hosts", "create-drawer"],
    queryFn: () => api.get<Host[]>("/api/hosts"),
    enabled: isOpen,
  });
  const snapshotsQuery = useQuery({
    queryKey: ["snapshots"],
    queryFn: () => api.get<SnapshotInfo[]>("/api/snapshots"),
    enabled: isOpen,
    retry: false,
  });

  // Firecracker, Docker, Process — only the runtimes the live fleet actually advertises (D25).
  const availableRuntimes = useMemo(() => {
    const fleetTiers = new Set((hostsQuery.data ?? []).flatMap((h) => h.tiers ?? []));
    return RUNTIMES.filter((r) => fleetTiers.has(r.value));
  }, [hostsQuery.data]);
  const snapshotGroups = useMemo(() => activeSnapshotGroups(snapshotsQuery.data ?? []), [snapshotsQuery.data]);

  const [name, setName] = useState("");
  const [snapshotName, setSnapshotName] = useState(prefillSnapshot ?? "");
  const [snapshotDrawerOpen, setSnapshotDrawerOpen] = useState(false);
  const [templateSource, setTemplateSource] = useState<"template" | "dockerfile">("template");
  const [dockerfile, setDockerfile] = useState("FROM node:22-bookworm\n");
  const [buildProgress, setBuildProgress] = useState<{ host: string; elapsedS: number } | null>(null);
  const [runtime, setRuntime] = useState("");
  const [trust, setTrust] = useState<"trusted" | "untrusted">("trusted");
  const [size, setSize] = useState<SizeName | "custom">(DEFAULT_SIZE);
  const [customCpus, setCustomCpus] = useState<number | null>(DEFAULT_SIZES.medium.cpus);
  const [customMem, setCustomMem] = useState<number | null>(DEFAULT_SIZES.medium.mem_mib);
  const [customDisk, setCustomDisk] = useState<number | null>(DEFAULT_SIZES.medium.disk_mib);
  const [workspacePath, setWorkspacePath] = useState(() => localStorage.getItem(WORKSPACE_KEY) ?? "");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [tools, setTools] = useState<SearchableItem[]>([]);
  const [egressAllow, setEgressAllow] = useState<SearchableItem[]>([]);
  const [autoStop, setAutoStop] = useState<number | null>(null);
  const [autoArchive, setAutoArchive] = useState<number | null>(null);
  const [autoDelete, setAutoDelete] = useState<number | null>(null);
  const [ephemeral, setEphemeral] = useState(false);
  const [maxAge, setMaxAge] = useState<number | null>(null);
  const [env, setEnv] = useState<KVRow[]>([]);
  const [labels, setLabels] = useState<KVRow[]>([]);

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Reopening with a different "New sandbox from this" template re-seeds the source
  // fields, and the runtime with it once the template's own runtime is known — the rest
  // of the drawer's state (already mounted for the Dialog's exit transition) is left
  // alone until the user submits or closes.
  useEffect(() => {
    if (!isOpen || !prefillSnapshot) return;
    setSnapshotName(prefillSnapshot);
    if (prefillSnapshot === "base") return;
    const g = snapshotGroups.find((x) => x.name === prefillSnapshot);
    if (g?.runtime && availableRuntimes.some((r) => r.value === g.runtime)) setRuntime(g.runtime);
  }, [isOpen, prefillSnapshot, snapshotGroups, availableRuntimes]);

  // Preselect Firecracker when the fleet has it, else the first runtime the fleet
  // advertises. Re-runs whenever the fleet changes under an already-open drawer.
  useEffect(() => {
    if (!isOpen || availableRuntimes.length === 0) return;
    if (availableRuntimes.some((r) => r.value === runtime)) return;
    setRuntime(availableRuntimes.find((r) => r.value === "remote")?.value ?? availableRuntimes[0].value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, availableRuntimes]);

  // The caller mounts this drawer with key={String(isOpen)}, so a fresh open is a fresh
  // component instance — every useState above already starts blank/default, no manual
  // reset needed on close.
  const close = () => onOpenChange(false);

  // Only templates (including "base") whose own runtime is the chosen one — a group's
  // runtime already names just the hosts that serve it there (see activeSnapshotGroups).
  const templateGroupsForRuntime = useMemo(
    () => snapshotGroups.filter((g) => g.runtime === runtime),
    [snapshotGroups, runtime],
  );
  const snapshotOptions = templateGroupsForRuntime.map((g) => {
    // "restore" (memory-snapshot boot) is a Firecracker concept only — Docker never sets it.
    const parts = [g.kind, ...(g.memorySnapshot && runtime === "remote" ? ["restore"] : []), ...(g.hosts.length ? [g.hosts.join(", ")] : [])];
    return { value: g.name, label: `${g.name}  ·  ${parts.join("  ·  ")}` };
  });

  const submit = async () => {
    const nextErrors: Record<string, string> = {};
    if (name.trim() && !NAME_RE.test(name.trim())) nextErrors.name = NAME_RE_HELP;
    if (!runtime) nextErrors.runtime = "No runtime is available from the connected fleet.";
    if (runtime !== "native" && templateSource === "dockerfile" && !dockerfile.trim()) nextErrors.dockerfile = "Required.";

    // Checked before anything else — including before the (~100s) inline Dockerfile
    // build — so a duplicate name never costs a build the create will reject anyway.
    if (name.trim() && !nextErrors.name) {
      try {
        const existing = await api.get<SandboxInfo[]>("/api/sandboxes");
        if (existing.some((sb) => sb.name === name.trim() && sb.state !== "destroyed")) {
          nextErrors.name = `A live sandbox is already named ${name.trim()}.`;
        }
      } catch {
        // best-effort pre-check; the server still enforces uniqueness on create
      }
    }

    setErrors(nextErrors);
    if (Object.keys(nextErrors).length) return;

    setSubmitting(true);
    setSubmitError(null);
    setBuildProgress(null);
    let builtTemplateName: string | undefined;
    try {
      let templateToUse = runtime === "native" ? undefined : snapshotName.trim() || undefined;

      if (runtime !== "native" && templateSource === "dockerfile") {
        const tplName = `${name.trim() || `sbx-${Date.now().toString(36)}`}-tpl`;
        await api.post("/api/snapshots", { name: tplName, source: { dockerfile }, runtime, memory_snapshot: runtime === "remote" });
        setBuildProgress({ host: "the fleet", elapsedS: 0 });
        await pollTemplateActive(tplName, (host, elapsedS) => setBuildProgress({ host, elapsedS }));
        setBuildProgress(null);
        templateToUse = tplName;
        builtTemplateName = tplName;
        void qc.invalidateQueries({ queryKey: ["snapshots"] });
      }

      const body = {
        template: templateToUse,
        workspace: workspacePath.trim() ? { host_path: workspacePath.trim() } : undefined,
        pi_session: `dashboard-${crypto.randomUUID()}`,
        name: name.trim() || undefined,
        labels: rowsToObject(labels),
        env: rowsToObject(env),
        isolation: runtime,
        trust,
        tools: tools.map((t) => t.label),
        egress_allow: egressAllow.map((t) => t.label),
        auto_stop_secs: autoStop ?? undefined,
        auto_archive_secs: autoArchive != null ? autoArchive * 60 : undefined,
        auto_delete_secs: ephemeral ? 0 : autoDelete ?? undefined,
        max_age_secs: maxAge != null ? maxAge * 60 : undefined,
        size: size === "custom" ? undefined : size,
        limits: size === "custom" ? { cpus: customCpus ?? DEFAULT_SIZES.medium.cpus, mem_mib: customMem ?? DEFAULT_SIZES.medium.mem_mib, disk_mib: customDisk ?? DEFAULT_SIZES.medium.disk_mib } : undefined,
      };
      const res = await api.post<{ id: string }>("/api/sandboxes", body);
      if (workspacePath.trim()) localStorage.setItem(WORKSPACE_KEY, workspacePath.trim());
      void qc.invalidateQueries({ queryKey: ["sandboxes"] });
      close();
      navigate(`/sandboxes/${res.id}`);
    } catch (err) {
      setBuildProgress(null);
      // The build already ran and produced a real, active template even though the
      // create that followed it failed (e.g. a name collision) — point at it rather
      // than making the user rebuild or dig through the Templates page.
      const hint = builtTemplateName ? ` Template ${builtTemplateName} was built; pick it under Existing template.` : "";
      if (err instanceof ApiError) {
        const field = fieldForApiError(err.status, err.message);
        if (field) setErrors((prev) => ({ ...prev, [field]: err.message + hint }));
        else setSubmitError(err.message + hint);
      } else {
        setSubmitError((err instanceof Error ? err.message : "Create failed") + hint);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
    <Drawer
      isOpen={isOpen}
      onOpenChange={(open) => (open ? onOpenChange(open) : close())}
      title="Create Sandbox"
      footer={
        <>
          <Button label="Cancel" variant="secondary" onClick={close} />
          <Button label="Create" onClick={submit} isLoading={submitting} />
        </>
      }
    >
      {submitError && <Banner status="error" title="Couldn't create the sandbox" description={submitError} />}
      {buildProgress && (
        <Banner status="info" title="Building template" description={`Building on ${buildProgress.host}… ${buildProgress.elapsedS} s`} />
      )}

      <TextInput
        label="Name"
        value={name}
        onChange={setName}
        placeholder="my-sandbox"
        description="Optional. If not provided, the sandbox ID is used as the name."
        isOptional
        status={errors.name ? { type: "error", message: errors.name } : undefined}
        width="100%"
      />

      {availableRuntimes.length === 0 && !hostsQuery.isLoading ? (
        <Notice title="No runtime available" tone="error">
          This control plane has no hosts registered — connect a qafas host first.
        </Notice>
      ) : availableRuntimes.length === 1 ? (
        <div className="sbx-field-group">
          <span className="sbx-field-label">Runtime</span>
          <span className="sbx-value">{`Runtime: ${availableRuntimes[0].label} (the only runtime in this fleet)`}</span>
        </div>
      ) : (
        <RadioList
          label="Runtime"
          value={runtime}
          onChange={setRuntime}
          status={errors.runtime ? { type: "error", message: errors.runtime } : undefined}
        >
          {availableRuntimes.map((r) => (
            <RadioListItem key={r.value} value={r.value} label={r.label} description={r.description} />
          ))}
        </RadioList>
      )}

      {runtime === "native" ? (
        <div className="sbx-field-group">
          <span className="sbx-field-label">Template</span>
          <span className="sbx-value">base (the host&rsquo;s toolchains)</span>
        </div>
      ) : (
        <DrawerSection title="Template">
          <SegmentedControl value={templateSource} onChange={(v) => setTemplateSource(v as "template" | "dockerfile")} label="Template source" layout="fill">
            <SegmentedControlItem value="template" label="Existing template" />
            <SegmentedControlItem value="dockerfile" label="Dockerfile" />
          </SegmentedControl>
          {templateSource === "template" ? (
            <>
              <Selector
                label="Template"
                isLabelHidden
                options={snapshotOptions}
                value={snapshotName}
                onChange={(v) => setSnapshotName(v ?? "")}
                hasClear
                placeholder="base (default)"
                width="100%"
                status={errors.snapshot ? { type: "error", message: errors.snapshot } : undefined}
              />
              <span className="sbx-field-help">
                Only active {RUNTIMES.find((r) => r.value === runtime)?.label ?? ""} templates are listed; base is the built-in image.{" "}
                <button type="button" className="sbx-link" onClick={() => setSnapshotDrawerOpen(true)}>Build a template first</button>
              </span>
            </>
          ) : (
            <>
              <TextArea
                label="Dockerfile"
                isLabelHidden
                value={dockerfile}
                onChange={setDockerfile}
                rows={8}
                width="100%"
                style={{ fontFamily: "var(--font-family-code)", fontSize: 12 }}
                status={errors.dockerfile ? { type: "error", message: errors.dockerfile } : undefined}
              />
              <span className="sbx-field-help">
                Built as template &ldquo;{name.trim() || "<generated>"}-tpl&rdquo; on the {RUNTIMES.find((r) => r.value === runtime)?.label ?? ""} hosts; the sandbox is created once it is active.
              </span>
            </>
          )}
        </DrawerSection>
      )}

      <DrawerSection title="Trust">
        <SegmentedControl value={trust} onChange={(v) => setTrust(v as "trusted" | "untrusted")} label="Trust" layout="fill">
          <SegmentedControlItem value="trusted" label="Trusted" />
          <SegmentedControlItem value="untrusted" label="Untrusted" />
        </SegmentedControl>
        <span className="sbx-field-help">Untrusted input never runs in the Process runtime.</span>
      </DrawerSection>

      <DrawerSection title="Size">
        <SegmentedControl value={size} onChange={(v) => setSize(v as SizeName | "custom")} label="Size" layout="fill">
          {SIZE_NAMES.map((s) => (
            <SegmentedControlItem key={s} value={s} label={s[0].toUpperCase() + s.slice(1)} />
          ))}
          <SegmentedControlItem value="custom" label="Custom" />
        </SegmentedControl>
        {size === "custom" ? (
          <>
            <div className="sbx-numrow">
              <span className="sbx-label">CPUs</span>
              <NumberInput label="CPUs" isLabelHidden value={customCpus} onChange={setCustomCpus} min={0.25} step={0.25} width="100%" />
            </div>
            <div className="sbx-numrow">
              <span className="sbx-label">Memory (MiB)</span>
              <NumberInput label="Memory MiB" isLabelHidden value={customMem} onChange={setCustomMem} min={128} step={128} width="100%" />
            </div>
            <div className="sbx-numrow">
              <span className="sbx-label">Disk (MiB)</span>
              <NumberInput label="Disk MiB" isLabelHidden value={customDisk} onChange={setCustomDisk} min={128} step={128} width="100%" />
            </div>
          </>
        ) : (
          <span className="sbx-field-help">
            {`${DEFAULT_SIZES[size].cpus} cpu · ${formatMiB(DEFAULT_SIZES[size].mem_mib)} · ${formatMiB(DEFAULT_SIZES[size].disk_mib)} disk`}
          </span>
        )}
        {errors.size && <span className="sbx-field-help" style={{ color: "var(--color-error)" }}>{errors.size}</span>}
      </DrawerSection>

      {runtime === "remote" && !advancedOpen ? (
        <div>
          <Button label="Advanced: set a workspace path" variant="ghost" size="sm" onClick={() => setAdvancedOpen(true)} />
        </div>
      ) : (
        <TextInput
          label="Workspace (optional)"
          value={workspacePath}
          onChange={setWorkspacePath}
          placeholder="/Users/me/repo"
          description={WORKSPACE_HELP[runtime] ?? WORKSPACE_HELP.native}
          isOptional
          status={errors.workspace ? { type: "error", message: errors.workspace } : undefined}
          width="100%"
        />
      )}

      <Tokenizer label="Tools" searchSource={toolSource} value={tools} onChange={(items) => setTools(items)} hasCreate placeholder="node@22, rg, git…" width="100%" />
      <Tokenizer label="Egress allow" searchSource={emptySource} value={egressAllow} onChange={(items) => setEgressAllow(items)} hasCreate placeholder="github.com, *.npmjs.org…" width="100%" />

      <DrawerSection title="Lifecycle">
        <div className="sbx-numrow">
          <span className="sbx-label">Sleep after idle (s)</span>
          <NumberInput label="Sleep after idle, seconds" isLabelHidden value={autoStop} onChange={setAutoStop} hasClear min={0} placeholder="Daemon default" width="100%" />
        </div>
        <div className="sbx-numrow">
          <span className="sbx-label">Auto-archive (min)</span>
          <NumberInput label="Auto-archive minutes" isLabelHidden value={autoArchive} onChange={setAutoArchive} hasClear min={0} placeholder="Disabled" width="100%" />
        </div>
        <div className="sbx-numrow">
          <span className="sbx-label">Delete after stopped (s)</span>
          <NumberInput
            label="Delete after stopped, seconds"
            isLabelHidden
            value={autoDelete}
            onChange={setAutoDelete}
            hasClear
            min={0}
            placeholder="Daemon default"
            isDisabled={ephemeral}
            width="100%"
          />
        </div>
        <div className="sbx-numrow">
          <span className="sbx-label">Wall-clock max age (min)</span>
          <NumberInput label="Max age minutes" isLabelHidden value={maxAge} onChange={setMaxAge} hasClear min={0} placeholder="Disabled" width="100%" />
        </div>
        <div className="sbx-stack-8" style={{ marginTop: 8 }}>
          <CheckboxInput label="Ephemeral" value={ephemeral} onChange={(checked) => setEphemeral(checked)} />
          <span className="sbx-field-help" style={{ paddingLeft: 26 }}>
            Automatically delete the sandbox the moment it stops.
          </span>
        </div>
      </DrawerSection>

      <KeyValueEditor label="Environment Variables" rows={env} onChange={setEnv} addLabel="Add Variable" hasEnvPaste />
      <KeyValueEditor label="Labels" rows={labels} onChange={setLabels} addLabel="Add Label" keyPlaceholder="key" valuePlaceholder="value" />
    </Drawer>
    {/* Sibling, not nested inside the Drawer above — two independent <dialog>s so
        closing/Esc on one never fights the other's open state. */}
    <CreateSnapshotDrawer isOpen={snapshotDrawerOpen} onOpenChange={setSnapshotDrawerOpen} />
    </>
  );
}
