import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { TextInput } from "@astryxdesign/core/TextInput";
import { TextArea } from "@astryxdesign/core/TextArea";
import { NumberInput } from "@astryxdesign/core/NumberInput";
import { Switch } from "@astryxdesign/core/Switch";
import { SegmentedControl, SegmentedControlItem } from "@astryxdesign/core/SegmentedControl";
import { RadioList, RadioListItem } from "@astryxdesign/core/RadioList";
import { Selector } from "@astryxdesign/core/Selector";
import { Button } from "@astryxdesign/core/Button";
import { Banner } from "@astryxdesign/core/Banner";
import { Drawer, DrawerSection } from "./Drawer";
import { Muted } from "./tables";
import { Notice, StatusDot } from "../ui";
import { api, ApiError } from "../lib/api";
import { RUNTIMES, NAME_RE, NAME_RE_HELP } from "../lib/types";
import type { Host, SandboxInfo, SnapshotInfo } from "../lib/types";

const POLL_INTERVAL_MS = 2000;

type Source = "image" | "dockerfile" | "sandbox";

// Only Firecracker and Docker hosts build templates (D26) — Process serves "base" only.
const BUILDABLE_RUNTIMES = RUNTIMES.filter((r) => r.value === "remote" || r.value === "vm");

const SANDBOX_HELP = "Captures memory and disk of a running sandbox of the chosen runtime; restores in milliseconds.";
const MEMORY_SNAPSHOT_HELP =
  "Boots the image once after the build and captures memory; sandboxes then start in tens of milliseconds instead of a kernel boot.";
const DOCKER_BUILD_HELP = "Built as a podman image on Docker hosts.";

export function CreateSnapshotDrawer({ isOpen, onOpenChange }: { isOpen: boolean; onOpenChange: (open: boolean) => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [runtime, setRuntime] = useState("");
  const [source, setSource] = useState<Source>("image");
  const [imageRef, setImageRef] = useState("");
  const [dockerfile, setDockerfile] = useState("FROM node:22-bookworm\n");
  const [sandboxId, setSandboxId] = useState<string | null>(null);
  const [warm, setWarm] = useState<number | null>(0);
  const [memorySnapshot, setMemorySnapshot] = useState(true);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [results, setResults] = useState<SnapshotInfo[] | null>(null);
  const [buildStartedAt, setBuildStartedAt] = useState<number | null>(null);
  const [elapsedS, setElapsedS] = useState(0);

  const stillBuilding = !!results && results.some((r) => r.state === "building");

  // Per-host build progress is a point-in-time snapshot from the create response —
  // it never updates on its own, so the drawer polls the same endpoint the Templates
  // page reads from until every row settles. Never stops watching a running build.
  useEffect(() => {
    if (!stillBuilding || !buildStartedAt || !name) return;
    const t = setTimeout(async () => {
      try {
        const fresh = await api.get<SnapshotInfo[]>(`/api/snapshots/${encodeURIComponent(name)}`);
        setResults(fresh);
      } catch {
        // host(s) unreachable this tick — keep the last known rows, try again next tick
      }
    }, POLL_INTERVAL_MS);
    return () => clearTimeout(t);
  }, [stillBuilding, buildStartedAt, name, results]);

  useEffect(() => {
    if (!stillBuilding || !buildStartedAt) return;
    const iv = setInterval(() => setElapsedS(Math.round((Date.now() - buildStartedAt) / 1000)), 1000);
    return () => clearInterval(iv);
  }, [stillBuilding, buildStartedAt]);

  const hostsQuery = useQuery({
    queryKey: ["hosts", "template-drawer"],
    queryFn: () => api.get<Host[]>("/api/hosts"),
    enabled: isOpen,
  });
  const availableRuntimes = useMemo(() => {
    const fleetTiers = new Set((hostsQuery.data ?? []).flatMap((h) => h.tiers ?? []));
    return BUILDABLE_RUNTIMES.filter((r) => fleetTiers.has(r.value));
  }, [hostsQuery.data]);

  // Preselect Firecracker when the fleet can build it there, else Docker — re-runs
  // whenever the fleet changes under an already-open drawer, same as Create Sandbox.
  useEffect(() => {
    if (!isOpen || availableRuntimes.length === 0) return;
    if (availableRuntimes.some((r) => r.value === runtime)) return;
    setRuntime(availableRuntimes.find((r) => r.value === "remote")?.value ?? availableRuntimes[0].value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, availableRuntimes]);

  const sandboxesQuery = useQuery({
    queryKey: ["sandboxes", "snapshot-drawer"],
    queryFn: () => api.get<SandboxInfo[]>("/api/sandboxes"),
    enabled: isOpen && source === "sandbox",
  });
  const liveSandboxes = (sandboxesQuery.data ?? []).filter((sb) => sb.state !== "destroyed" && sb.isolation === runtime);

  const close = () => {
    onOpenChange(false);
    setName("");
    setRuntime("");
    setSource("image");
    setImageRef("");
    setDockerfile("FROM node:22-bookworm\n");
    setSandboxId(null);
    setWarm(0);
    setMemorySnapshot(true);
    setErrors({});
    setSubmitError(null);
    setResults(null);
    setBuildStartedAt(null);
    setElapsedS(0);
  };

  const submit = async () => {
    const next: Record<string, string> = {};
    if (!NAME_RE.test(name)) next.name = NAME_RE_HELP;
    if (!runtime) next.runtime = "No runtime in this fleet can build templates.";
    if (source === "image" && (!imageRef.trim() || !imageRef.includes(":") || imageRef.trim().endsWith(":latest"))) {
      next.image = 'Must include a tag (e.g. "node:22-bookworm"); "latest" is not allowed.';
    }
    if (source === "dockerfile" && !dockerfile.trim()) next.dockerfile = "Required.";
    if (source === "sandbox" && !sandboxId) next.sandbox = "Pick a sandbox.";
    setErrors(next);
    if (Object.keys(next).length) return;

    setSubmitting(true);
    setSubmitError(null);
    try {
      const source_: Record<string, string> =
        source === "image" ? { image: imageRef.trim() } : source === "dockerfile" ? { dockerfile } : { sandbox_id: sandboxId! };
      const res = await api.post<SnapshotInfo[]>("/api/snapshots", {
        name,
        source: source_,
        runtime,
        warm: warm ?? 0,
        memory_snapshot: runtime === "remote" ? memorySnapshot : false,
      });
      void qc.invalidateQueries({ queryKey: ["snapshots"] });
      setResults(res);
      setBuildStartedAt(Date.now());
      setElapsedS(0);
    } catch (err) {
      setSubmitError(
        err instanceof ApiError && err.status === 404
          ? "Needs a v3 host — templates aren't served by the connected control plane yet."
          : err instanceof Error
            ? err.message
            : "Create failed",
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Drawer
      isOpen={isOpen}
      onOpenChange={(open) => (open ? onOpenChange(open) : close())}
      title={results ? "Building template" : "Create Template"}
      footer={
        results ? (
          <Button label="Done" onClick={close} />
        ) : (
          <>
            <Button label="Cancel" variant="secondary" onClick={close} />
            <Button label="Create" onClick={submit} isLoading={submitting} isDisabled={availableRuntimes.length === 0 && !hostsQuery.isLoading} />
          </>
        )
      }
    >
      {results ? (
        <>
          <Banner
            status={stillBuilding ? "success" : results.some((r) => r.state === "error") ? "error" : "success"}
            title={stillBuilding ? `Building ${name}` : `${name} finished building`}
            description={
              stillBuilding
                ? `Per host — building can take a while (${elapsedS}s so far). This view updates every ${POLL_INTERVAL_MS / 1000}s; the Templates page also updates live.`
                : "Every host has settled — active or errored, see below."
            }
          />
          <div className="sbx-stack-8">
            {results.map((r) => (
              <div key={r.host_id ?? r.name} className="sbx-row" style={{ gap: 8 }}>
                <span className="mono" style={{ fontSize: 12.5, minWidth: 100 }}>{r.host_id ?? "—"}</span>
                <StatusDot tone={r.state === "error" ? "danger" : r.state === "active" ? "ready" : "busy"} label={r.state} />
                {r.state === "error" && <Muted>{r.error || "build failed"}</Muted>}
              </div>
            ))}
          </div>
        </>
      ) : (
        <>
          {submitError && <Banner status="error" title="Couldn't create the template" description={submitError} />}

          {availableRuntimes.length === 0 && !hostsQuery.isLoading ? (
            <Notice title="No runtime can build templates" tone="error">
              Templates build only on Firecracker or Docker hosts — connect one first.
            </Notice>
          ) : (
            availableRuntimes.length > 1 && (
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
            )
          )}

          <DrawerSection title="Source">
            <SegmentedControl value={source} onChange={(v) => setSource(v as Source)} label="Source" layout="fill">
              <SegmentedControlItem value="image" label="Image" />
              <SegmentedControlItem value="dockerfile" label="Dockerfile" />
              <SegmentedControlItem value="sandbox" label="Checkpoint" />
            </SegmentedControl>

            {source === "image" && (
              <>
                <TextInput
                  label="Image"
                  isLabelHidden
                  value={imageRef}
                  onChange={setImageRef}
                  placeholder="node:22-bookworm"
                  status={errors.image ? { type: "error", message: errors.image } : undefined}
                  width="100%"
                />
                <span className="sbx-field-help">
                  Must include a tag (e.g. node:22-bookworm) or a digest. The tag &ldquo;latest&rdquo; is not allowed.
                </span>
              </>
            )}
            {source === "dockerfile" && (
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
            )}
            {source === "sandbox" && (
              <>
                <Selector
                  label="Sandbox"
                  isLabelHidden
                  options={liveSandboxes.map((sb) => ({ value: sb.id, label: sb.name || sb.id }))}
                  value={sandboxId}
                  onChange={setSandboxId}
                  hasClear
                  placeholder="Select a live sandbox…"
                  width="100%"
                  status={errors.sandbox ? { type: "error", message: errors.sandbox } : undefined}
                />
                <span className="sbx-field-help">{SANDBOX_HELP}</span>
              </>
            )}
          </DrawerSection>

          <TextInput
            label="Name"
            value={name}
            onChange={setName}
            placeholder="my-template"
            description="Lowercase letters, digits, . _ - (max 64 chars)."
            isRequired
            status={errors.name ? { type: "error", message: errors.name } : undefined}
            width="100%"
          />

          <DrawerSection title="Warm pool">
            <NumberInput
              label="Keep warm (sandboxes)"
              value={warm}
              onChange={setWarm}
              min={0}
              step={1}
              isIntegerOnly
              hasClear
              width="100%"
            />
            <span className="sbx-field-help">Sandboxes the pool keeps restored and ready for this template on each host.</span>
            {runtime === "remote" && (
              <>
                <Switch label="Memory snapshot: start by restore" value={memorySnapshot} onChange={setMemorySnapshot} />
                <span className="sbx-field-help">{MEMORY_SNAPSHOT_HELP}</span>
              </>
            )}
            {runtime === "vm" && <span className="sbx-field-help">{DOCKER_BUILD_HELP}</span>}
          </DrawerSection>
        </>
      )}
    </Drawer>
  );
}
