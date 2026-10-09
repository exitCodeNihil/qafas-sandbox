import { useState } from "react";
import { useParams, useSearchParams, Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@astryxdesign/core/Button";
import { pixel, proportional } from "@astryxdesign/core/Table";
import { NumberInput } from "@astryxdesign/core/NumberInput";
import { TextInput } from "@astryxdesign/core/TextInput";
import { TabList, Tab } from "@astryxdesign/core/TabList";
import { Banner } from "@astryxdesign/core/Banner";
import { IconButton } from "@astryxdesign/core/IconButton";
import { Tooltip } from "@astryxdesign/core/Tooltip";
import { Page, Query, Loading, ErrorState, NeedsV3 } from "../components/Page";
import { Ago, Muted, StateCell } from "../components/tables";
import { EventLine } from "./SessionDetail";
import { SandboxRowMenu } from "../components/SandboxRowMenu";
import { EVENT_CHIPS, chipOf } from "../lib/eventCategory";
import { api, ApiError } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { timerLabel } from "../lib/sandboxActions";
import { Card, CodeBlock, DataTable, EmptyState, FilterChip, KeyValueGrid, Notice, Tag, Tags, Toolbar } from "../ui";
import { IconCopy, IconExternalLink } from "../components/icons";
import { runtimeLabel } from "../lib/types";
import type { SandboxInfo, Event, LiveProcess, SessionRow, PreviewInfo } from "../lib/types";
import { formatMiB, formatBytes } from "../lib/format";

type TabKey = "overview" | "preview" | "processes" | "events" | "sessions";

const processColumns = [
  { key: "pid", header: "PID", width: pixel(80), align: "end" as const, renderCell: (p: LiveProcess) => <span className="mono" style={{ fontSize: 12.5 }}>{p.pid}</span> },
  { key: "ppid", header: "PPID", width: pixel(80), align: "end" as const, renderCell: (p: LiveProcess) => <span className="mono" style={{ fontSize: 12.5 }}>{p.ppid}</span> },
  {
    key: "argv",
    header: "Command",
    width: proportional(1, { minWidth: 240 }),
    renderCell: (p: LiveProcess) => (
      <span className="mono sbx-truncate" style={{ fontSize: 12.5 }} title={p.argv.join(" ")}>
        {p.argv.join(" ")}
      </span>
    ),
  },
  {
    key: "started_at",
    header: "Started",
    width: pixel(110),
    renderCell: (p: LiveProcess) => <Ago value={p.started_at} />,
  },
  {
    key: "rss_kb",
    header: "RSS",
    width: pixel(90),
    align: "end" as const,
    renderCell: (p: LiveProcess) => <span className="mono" style={{ fontSize: 12.5 }}>{p.rss_kb ? `${(p.rss_kb / 1024).toFixed(1)}MB` : "—"}</span>,
  },
];

/** Lifecycle timer in minutes — only rendered when the sandbox has one set. */
function timerValue(secs?: number | null): string | null {
  if (secs === undefined || secs === null) return null;
  return secs === 0 ? "0 (immediate)" : `${Math.round(secs / 60)}m`;
}

/** `mini · 1 cpu · 1 GiB · 1 GiB disk` — absent until a v5 daemon reports `limits`. */
function sizeLine(sb: SandboxInfo): string | null {
  if (!sb.limits) return null;
  return `${sb.size || "custom"} · ${sb.limits.cpus} cpu · ${formatMiB(sb.limits.mem_mib)} · ${formatMiB(sb.limits.disk_mib)} disk`;
}

/** `mem 543 MiB / 1 GiB · cpu 1.9 s · 13 pids · disk 203 MiB` — "—" until the first sample. */
function usageLine(sb: SandboxInfo): string {
  if (!sb.usage) return "—";
  const u = sb.usage;
  const memLimit = sb.limits ? ` / ${formatMiB(sb.limits.mem_mib)}` : "";
  return `mem ${formatBytes(u.mem_bytes)}${memLimit} · cpu ${(u.cpu_millis / 1000).toFixed(1)} s · ${u.pids} pids · disk ${formatBytes(u.disk_bytes)}`;
}

function Header({ sb }: { sb: SandboxInfo }) {
  const labels = Object.entries(sb.labels ?? {});
  return (
    <Card>
      <div className="sbx-stack-24">
        <div className="sbx-row-wrap" style={{ gap: 12 }}>
          <StateCell state={sb.state} />
          {sb.isolation && <Tag title="Runtime">{`Runtime: ${runtimeLabel(sb.isolation)}`}</Tag>}
          <Tag mono>{sb.template}</Tag>
          {sb.trust && <Tag tone={sb.trust === "trusted" ? "warning" : undefined}>{sb.trust}</Tag>}
          {sb.size && <Tag mono title="Size">{sb.size}</Tag>}
        </div>

        {sb.state === "destroyed" && <Notice title="Destroyed">This sandbox is gone; its history stays below for reference.</Notice>}

        <KeyValueGrid
          columns={4}
          items={[
            { label: "Host", value: sb.host_id },
            { label: "Backend", value: sb.backend },
            { label: "Size", value: sizeLine(sb) ? <span className="mono">{sizeLine(sb)}</span> : null },
            { label: "Usage", value: sb.limits ? <span className="mono">{usageLine(sb)}</span> : null },
            {
              label: "Enforcement",
              value: sb.enforcement
                ? sb.enforcement === "daemon"
                  ? <Tag tone="warning" title="qafas's watchdog enforces memory and disk; CPU is not capped on macOS native">daemon</Tag>
                  : <Tag>{sb.enforcement}</Tag>
                : null,
            },
            {
              label: "Session",
              value: sb.pi_session ? (
                <Link to={`/sessions/${sb.pi_session}`} className="mono sbx-link">
                  {sb.pi_session}
                </Link>
              ) : null,
            },
            {
              label: "API key",
              value: sb.api_key_name ? (
                <Link to={`/keys/${sb.api_key_id}`} className="sbx-link">
                  {sb.api_key_name}
                </Link>
              ) : (
                "admin"
              ),
            },
            { label: "Created", value: <Ago value={sb.created_at} /> },
            { label: "Last activity", value: <Ago value={sb.last_activity ?? sb.created_at} /> },
            { label: "Timer", value: timerLabel(sb) },
            { label: "Auto-stop", value: timerValue(sb.auto_stop_secs) },
            { label: "Auto-archive", value: timerValue(sb.auto_archive_secs) },
            { label: "Auto-delete", value: timerValue(sb.auto_delete_secs) },
            { label: "Max age", value: timerValue(sb.max_age_secs) },
            {
              label: "Workspace",
              wide: true,
              value: (
                <span className="mono" style={{ fontSize: 12.5 }}>
                  {sb.workspace_path}
                </span>
              ),
            },
            labels.length > 0
              ? {
                  label: "Labels",
                  wide: true,
                  value: (
                    <Tags>
                      {labels.map(([k, v]) => (
                        <Tag key={k} mono>{`${k}=${v}`}</Tag>
                      ))}
                    </Tags>
                  ),
                }
              : null,
          ]}
        />
      </div>
    </Card>
  );
}

function OverviewTab({ sb, eventsCount }: { sb: SandboxInfo; eventsCount: number }) {
  const envKeys = Object.keys(sb.env ?? {});
  return (
    <Card>
      <div className="sbx-stack-24">
        <KeyValueGrid
          columns={3}
          items={[
            { label: "Endpoint", value: sb.endpoint ? <span className="mono" style={{ fontSize: 12.5 }}>{sb.endpoint}</span> : null },
            { label: "Events recorded", value: <span className="mono">{eventsCount.toLocaleString()}</span> },
            { label: "Environment variables", value: <span className="mono">{envKeys.length}</span> },
          ]}
        />
        {envKeys.length > 0 && (
          <div className="sbx-stack-8">
            <span className="sbx-field-label">Environment</span>
            <Tags>
              {envKeys.map((k) => (
                <Tag key={k} mono>{`${k}=••••••`}</Tag>
              ))}
            </Tags>
          </div>
        )}
      </div>
    </Card>
  );
}

function PreviewTab({ id, disabled }: { id: string; disabled: boolean }) {
  const [port, setPort] = useState<number | null>(null);
  const [entries, setEntries] = useState<PreviewInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    if (!port || port < 1 || port > 65535) {
      setError("Enter a valid port (1–65535).");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const info = await api.post<PreviewInfo>(`/api/sandboxes/${id}/preview`, { port });
      setEntries((prev) => [info, ...prev]);
      setPort(null);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 404 ? "needs-v3" : err instanceof Error ? err.message : "Failed to create preview URL");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="sbx-stack-24">
      <Card>
        <div className="sbx-stack-16">
          <div className="sbx-row" style={{ gap: 8, alignItems: "flex-end" }}>
            <NumberInput label="Port" value={port} onChange={setPort} hasClear placeholder="3000" min={1} max={65535} isDisabled={disabled} width={140} />
            <Button label="Create preview URL" onClick={create} isLoading={busy} isDisabled={disabled} />
          </div>
          {error === "needs-v3" && <NeedsV3 what="Preview" />}
          {error && error !== "needs-v3" && <Banner status="error" title="Couldn't create preview URL" description={error} />}
        </div>
      </Card>

      {entries.length === 0 ? (
        <EmptyState title="No preview URLs" description="Expose a port from inside the sandbox to get a signed, expiring URL for it." />
      ) : (
        <Card padding="flush">
          <ul className="sbx-list">
            {entries.map((p) => (
              <li key={p.token} style={{ minHeight: 56 }}>
                <Tag mono>{`:${p.port}`}</Tag>
                <span className="mono sbx-truncate" style={{ flex: 1, fontSize: 12.5 }}>
                  {p.url}
                </span>
                <Muted>valid until {new Date(p.expires_at).toLocaleString()}</Muted>
                <Tooltip content="Copy">
                  <IconButton label="Copy URL" variant="ghost" size="sm" icon={<IconCopy width={14} height={14} />} onClick={() => navigator.clipboard?.writeText(p.url)} />
                </Tooltip>
                <Tooltip content="Open">
                  <IconButton label="Open URL" variant="ghost" size="sm" icon={<IconExternalLink width={14} height={14} />} onClick={() => window.open(p.url, "_blank", "noopener,noreferrer")} />
                </Tooltip>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

type ExecResult = { exit: number | null; stdout: string; stderr: string; duration_ms: number };

/** Why the sandbox can't run a command right now — null means it can. `stopped` is
 * allowed (the daemon wakes it on use), everything else needs a live sandbox. */
function execDisabledReason(state: SandboxInfo["state"]): string | null {
  if (state === "ready" || state === "busy" || state === "stopped") return null;
  if (state === "destroyed") return "This sandbox is destroyed.";
  return `Not available while ${state}.`;
}

/** One-line command + Run, posting to the daemon's exec route and rendering the
 * result — the detail page's only way to actually run something (previously nothing
 * on this page could start a process). */
function RunCommandPanel({ sandbox }: { sandbox: SandboxInfo }) {
  const [cmd, setCmd] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ExecResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const disabledReason = execDisabledReason(sandbox.state);

  const run = async () => {
    if (!cmd.trim() || disabledReason) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.post<ExecResult>(`/api/sandboxes/${sandbox.id}/exec`, { cmd: cmd.trim() });
      setResult(res);
    } catch (err) {
      setError(err instanceof ApiError && err.status === 404 ? "needs-v3" : err instanceof Error ? err.message : "Command failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <div className="sbx-stack-16">
        <span className="sbx-field-label">Run command</span>
        <div className="sbx-row" style={{ gap: 8, alignItems: "flex-end" }}>
          <TextInput
            label="Command"
            isLabelHidden
            value={cmd}
            onChange={setCmd}
            onEnter={run}
            placeholder="echo hello"
            description="Runs in the sandbox home."
            isDisabled={!!disabledReason}
            width="100%"
          />
          <Button label="Run" onClick={run} isLoading={busy} isDisabled={!!disabledReason || !cmd.trim()} />
        </div>
        {disabledReason && <Muted>{disabledReason}</Muted>}
        {!disabledReason && sandbox.state === "stopped" && <Muted>Running a command wakes the sandbox.</Muted>}
        {error === "needs-v3" && <NeedsV3 what="Run command" />}
        {error && error !== "needs-v3" && <Banner status="error" title="Command failed" description={error} />}
        {result && (
          <div className="sbx-stack-8">
            <span className="mono" style={{ fontSize: 12.5, color: "var(--color-text-secondary)" }}>
              {`exit ${result.exit ?? "—"} · ${result.duration_ms}ms`}
            </span>
            <CodeBlock code={result.stdout || "(no stdout)"} language="stdout" />
            {result.stderr && <CodeBlock code={result.stderr} language="stderr" />}
          </div>
        )}
      </div>
    </Card>
  );
}

const sessionColumns = [
  {
    key: "pi_session",
    header: "Session",
    width: proportional(2, { minWidth: 180 }),
    renderCell: (s: SessionRow) => (
      <Link to={`/sessions/${s.pi_session}`} className="mono sbx-link sbx-truncate" style={{ fontSize: 12.5 }}>
        {s.pi_session}
      </Link>
    ),
  },
  { key: "execs", header: "Execs", width: pixel(80), align: "end" as const, renderCell: (s: SessionRow) => <span className="mono" style={{ fontSize: 12.5 }}>{s.execs}</span> },
  {
    key: "last_ts",
    header: "Last activity",
    width: pixel(130),
    renderCell: (s: SessionRow) => <Ago value={s.last_ts} />,
  },
];

function SessionsTab({ sandboxId }: { sandboxId: string }) {
  const query = useQuery({ queryKey: ["sessions", "for-sandbox"], queryFn: () => api.get<SessionRow[]>("/api/sessions?limit=200") });
  return (
    <Query query={query}>
      {(sessions) => {
        const rows = sessions.filter((s) => (s.sandbox_ids ?? []).includes(sandboxId));
        if (rows.length === 0) return <EmptyState title="No shells" description="Persistent shells opened through the SDK." />;
        return <DataTable data={rows} idKey="pi_session" columns={sessionColumns} />;
      }}
    </Query>
  );
}

export default function SandboxDetailPage() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as TabKey | null) ?? "overview";
  const setTab = (t: string) => setParams((p) => { p.set("tab", t); return p; }, { replace: true });

  const [events, setEvents] = useState<Event[]>([]);
  const [activeChips, setActiveChips] = useState<Set<string>>(new Set(EVENT_CHIPS.map((c) => c.key)));

  const query = useQuery({
    queryKey: ["sandbox", id],
    queryFn: () => api.get<SandboxInfo>(`/api/sandboxes/${id}`),
    enabled: !!id,
    refetchInterval: 5000,
  });

  const processesQuery = useQuery({
    queryKey: ["sandbox-processes", id],
    queryFn: () => api.get<LiveProcess[]>(`/api/sandboxes/${id}/processes`),
    enabled: !!id && query.data?.state !== "destroyed" && tab === "processes",
    refetchInterval: 3000,
  });

  const eventsQuery = useQuery({
    queryKey: ["sandbox-events", id],
    queryFn: () => api.get<Event[]>(`/api/sandboxes/${id}/events`),
    enabled: !!id,
  });

  useEventStream({ sandbox_id: id }, (event) => {
    if (event.sandbox_id === id) {
      setEvents((prev) => [event, ...prev]);
      void qc.invalidateQueries({ queryKey: ["sandbox", id] });
    }
  });

  const allEvents = [...(eventsQuery.data ?? []), ...events.filter((e) => !(eventsQuery.data ?? []).some((fe) => fe.id === e.id))].sort(
    (a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime(),
  );
  const filteredEvents = allEvents.filter((e) => {
    const c = chipOf(e.type);
    return c === null || activeChips.has(c);
  });

  const toggleChip = (key: string) =>
    setActiveChips((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const sb = query.data;
  const named = !!sb?.name && sb.name !== sb.id;

  return (
    <Page
      title={sb?.name || id || ""}
      id={named ? sb!.id : undefined}
      description={named ? undefined : "Sandbox"}
      action={sb && sb.state !== "destroyed" ? <SandboxRowMenu sandbox={sb} variant="secondary" /> : undefined}
    >
      <Query query={query}>
        {(sandbox) => (
          <>
            <Header sb={sandbox} />

            {sandbox.state !== "destroyed" && <RunCommandPanel sandbox={sandbox} />}

            <div className="sbx-stack-24">
              <div className="sbx-tabs">
                <TabList value={tab} onChange={setTab} role="tablist">
                  <Tab value="overview" label="Overview" role="tab" aria-selected={tab === "overview"} />
                  <Tab value="preview" label="Preview" role="tab" aria-selected={tab === "preview"} />
                  <Tab value="processes" label="Processes" role="tab" aria-selected={tab === "processes"} />
                  <Tab value="events" label={`Events ${allEvents.length}`} role="tab" aria-selected={tab === "events"} />
                  <Tab value="sessions" label="Shells" role="tab" aria-selected={tab === "sessions"} />
                </TabList>
              </div>

              <div role="tabpanel" id={`sbx-tabpanel-${tab}`}>
              {tab === "overview" && <OverviewTab sb={sandbox} eventsCount={allEvents.length} />}

              {tab === "preview" && <PreviewTab id={sandbox.id} disabled={sandbox.state === "destroyed"} />}

              {tab === "processes" &&
                (sandbox.state === "destroyed" ? (
                  <EmptyState title="No process data" description="This sandbox is destroyed — nothing is running." />
                ) : (
                  <>
                    {processesQuery.isLoading && <Loading label="Loading processes" />}
                    {processesQuery.error && <ErrorState error={processesQuery.error} onRetry={() => processesQuery.refetch()} />}
                    {!processesQuery.isLoading && !processesQuery.error && (
                      <DataTable data={processesQuery.data ?? []} idKey="pid" empty="No processes running." columns={processColumns} />
                    )}
                  </>
                ))}

              {tab === "events" && (
                <div className="sbx-stack-16">
                  <Toolbar>
                    {EVENT_CHIPS.map((c) => (
                      <FilterChip key={c.key} label={c.label} isActive={activeChips.has(c.key)} onClick={() => toggleChip(c.key)} />
                    ))}
                  </Toolbar>
                  {eventsQuery.isLoading && filteredEvents.length === 0 && <Loading label="Loading events" />}
                  {eventsQuery.error && <ErrorState error={eventsQuery.error} onRetry={() => eventsQuery.refetch()} />}
                  {!eventsQuery.isLoading && filteredEvents.length === 0 && (
                    <EmptyState title="Nothing to show" description="No events match the current filters." />
                  )}
                  {filteredEvents.length > 0 && (
                    <div className="sbx-events">
                      <div className="sbx-events-scroll">
                        {filteredEvents.map((event) => (
                          <EventLine key={event.id} event={event} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {tab === "sessions" && <SessionsTab sandboxId={sandbox.id} />}
              </div>
            </div>
          </>
        )}
      </Query>
    </Page>
  );
}
