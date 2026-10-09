import { useEffect, useMemo, useRef, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { TabList, Tab } from "@astryxdesign/core/TabList";
import { proportional, pixel } from "@astryxdesign/core/Table";
import { Page, Query, Loading } from "../components/Page";
import { TraceWaterfall } from "../components/TraceWaterfall";
import { Ago, Muted, SeverityTag } from "../components/tables";
import { Card, Chevron, DataTable, EmptyState, FilterChip, KeyValueGrid, StatusDot, Tag, Tags, Toolbar } from "../ui";
import { api } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { SEVERITIES } from "../lib/severity";
import { EVENT_CHIPS, chipOf } from "../lib/eventCategory";
import { attrString } from "../lib/types";
import { summarizeEvent, durationLabel } from "../lib/format";
import type { AlertData, Event, OtlpSpan, OtlpTrace, ProcessNode, SessionDetail as SessionDetailT } from "../lib/types";

type TabKey = "timeline" | "trace" | "processes" | "files" | "network" | "alerts";

// ---------------------------------------------------------------- Timeline

type Row = { kind: "solo"; event: Event } | { kind: "group"; toolCallId: string; events: Event[] };

function buildRows(events: Event[]): Row[] {
  const order: Row[] = [];
  const groups = new Map<string, Event[]>();
  for (const e of events) {
    if (!e.tool_call_id) {
      order.push({ kind: "solo", event: e });
      continue;
    }
    let bucket = groups.get(e.tool_call_id);
    if (!bucket) {
      bucket = [];
      groups.set(e.tool_call_id, bucket);
      order.push({ kind: "group", toolCallId: e.tool_call_id, events: bucket });
    }
    bucket.push(e);
  }
  return order;
}

function groupTitle(events: Event[]): string {
  const start = events.find((e) => e.type === "exec.start");
  if (start) return String((start.data as { cmd?: string }).cmd ?? "exec");
  const write = events.find((e) => e.type === "file.write");
  if (write) return `write ${(write.data as { path?: string }).path ?? ""}`;
  const nav = events.find((e) => e.type === "browser.navigate");
  if (nav) return `navigate ${(nav.data as { url?: string }).url ?? ""}`;
  return events[0]?.type ?? "tool call";
}

/**
 * One timeline row on a fixed grid: 90px time · 110px monospace type ·
 * message · a chevron that reveals the raw payload. The type is a column,
 * not a coloured badge — severity is the only thing that gets colour.
 */
export function EventLine({ event }: { event: Event }) {
  const [open, setOpen] = useState(false);
  const summary = summarizeEvent(event);
  const severity = event.type === "security.alert" ? (event.data as AlertData).severity : null;
  return (
    <div className="sbx-event">
      <span className="sbx-event-time">{new Date(event.ts).toLocaleTimeString()}</span>
      <span className="sbx-event-type" title={event.type}>
        {event.type}
      </span>
      <span className="sbx-event-msg">
        <span title={summary}>{summary || "—"}</span>
        {severity && <SeverityTag severity={severity} />}
      </span>
      <button type="button" className="sbx-event-toggle" onClick={() => setOpen((o) => !o)} aria-label="Toggle details" aria-expanded={open}>
        <Chevron isOpen={open} />
      </button>
      {open && <pre className="sbx-event-data">{JSON.stringify(event.data, null, 2)}</pre>}
    </div>
  );
}

function ToolCallGroup({
  row,
  isHighlighted,
  innerRef,
}: {
  row: Extract<Row, { kind: "group" }>;
  isHighlighted: boolean;
  innerRef: (el: HTMLDivElement | null) => void;
}) {
  const [open, setOpen] = useState(true);
  const alerts = row.events.filter((e) => e.type === "security.alert");
  const worst = alerts
    .map((e) => (e.data as AlertData).severity)
    .sort((a, b) => SEVERITIES.indexOf(a) - SEVERITIES.indexOf(b))[0];
  return (
    <div ref={innerRef}>
      <button type="button" className="sbx-group" data-highlight={isHighlighted || undefined} onClick={() => setOpen((o) => !o)}>
        <span className="sbx-group-id">{row.toolCallId}</span>
        <span className="sbx-group-title" title={groupTitle(row.events)}>
          {groupTitle(row.events)}
        </span>
        <span className="sbx-group-meta">
          <span>{row.events.length} events</span>
          {worst && <SeverityTag severity={worst} count={alerts.length} />}
          <Chevron isOpen={open} />
        </span>
      </button>
      {open && row.events.map((e) => <EventLine key={e.id} event={e} />)}
    </div>
  );
}

function Timeline({ sessionId, events, isLoading, highlightToolCall }: { sessionId: string; events: Event[]; isLoading: boolean; highlightToolCall: string | null }) {
  const [active, setActive] = useState<Set<string>>(new Set(EVENT_CHIPS.map((c) => c.key)));
  const [live, setLive] = useState<Event[]>([]);
  const groupRefs = useRef(new Map<string, HTMLDivElement>());

  useEventStream({ pi_session: sessionId }, (event) => {
    if (event.pi_session === sessionId) setLive((prev) => (prev.some((p) => p.id === event.id) ? prev : [...prev, event]));
  });

  const merged = useMemo(() => {
    const byId = new Map(events.map((e) => [e.id, e]));
    for (const e of live) byId.set(e.id, e);
    return [...byId.values()].sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime());
  }, [events, live]);

  const filtered = useMemo(
    () => merged.filter((e) => { const c = chipOf(e.type); return c === null || active.has(c); }),
    [merged, active],
  );
  const rows = useMemo(() => buildRows(filtered), [filtered]);

  useEffect(() => {
    if (!highlightToolCall) return;
    const el = groupRefs.current.get(highlightToolCall);
    el?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [highlightToolCall, rows.length]);

  const toggle = (key: string) =>
    setActive((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  return (
    <div className="sbx-stack-16">
      <Toolbar>
        {EVENT_CHIPS.map((c) => (
          <FilterChip key={c.key} label={c.label} isActive={active.has(c.key)} onClick={() => toggle(c.key)} />
        ))}
      </Toolbar>
      {isLoading && <Loading label="Loading timeline" />}
      {!isLoading && rows.length === 0 && <EmptyState title="Nothing to show" description="No events match the current filters." />}
      {rows.length > 0 && (
        <div className="sbx-events">
          <div className="sbx-events-scroll">
            {rows.map((row) =>
              row.kind === "solo" ? (
                <EventLine key={row.event.id} event={row.event} />
              ) : (
                <ToolCallGroup
                  key={row.toolCallId}
                  row={row}
                  isHighlighted={row.toolCallId === highlightToolCall}
                  innerRef={(el) => {
                    if (el) groupRefs.current.set(row.toolCallId, el);
                  }}
                />
              ),
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Processes

function fmtDuration(startTs: string, endTs: string | null): string {
  if (!endTs) return "running";
  const ms = new Date(endTs).getTime() - new Date(startTs).getTime();
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`;
}

/** Indentation guides: a vertical rule per depth level, like a file tree. */
function ProcessNodeRow({ node }: { node: ProcessNode }) {
  const [open, setOpen] = useState(true);
  const children = node.children ?? [];
  return (
    <div>
      <div className="sbx-event" style={{ gridTemplateColumns: "56px minmax(0, 1fr) auto 20px" }}>
        <span className="sbx-event-time">{node.pid}</span>
        <span className="sbx-event-msg">
          <span title={node.argv.join(" ")}>{node.argv.join(" ")}</span>
        </span>
        <span className="sbx-group-meta">
          <span className="mono" style={{ fontSize: 12 }}>{fmtDuration(node.start_ts, node.end_ts)}</span>
          {node.signal ? (
            <StatusDot tone="danger" label={`signal ${node.signal}`} />
          ) : node.exit !== null ? (
            <StatusDot tone={node.exit === 0 ? "ready" : "danger"} label={`exit ${node.exit}`} />
          ) : null}
          {node.alert && <SeverityTag severity={node.alert.severity} />}
        </span>
        {children.length > 0 ? (
          <button type="button" className="sbx-event-toggle" onClick={() => setOpen((o) => !o)} aria-label="Toggle children" aria-expanded={open}>
            <Chevron isOpen={open} />
          </button>
        ) : (
          <span />
        )}
      </div>
      {open && children.length > 0 && (
        <div className="sbx-tree">
          {/* pid alone is not unique over a long session — pair it with the index. */}
          {children.map((c, i) => (
            <ProcessNodeRow key={`${c.pid}-${i}`} node={c} />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Trace

function SpanPanel({ span }: { span: OtlpSpan | null }) {
  if (!span) {
    return (
      <Card>
        <p className="sbx-section-desc" style={{ margin: 0 }}>
          Select a span in the waterfall to inspect its attributes and events.
        </p>
      </Card>
    );
  }
  return (
    <Card>
      <div className="sbx-stack-16">
        <h3 className="sbx-section-title">{span.name}</h3>
        <KeyValueGrid
          columns={2}
          items={span.attributes.map((a) => ({
            label: a.key,
            value: <span className="mono" style={{ fontSize: 12 }}>{attrString(span.attributes, a.key)}</span>,
          }))}
        />
        {span.events.length > 0 && (
          <div className="sbx-stack-8">
            <span className="sbx-field-label">Span events</span>
            {span.events.map((e, i) => (
              <pre key={i} className="sbx-event-data" style={{ gridColumn: "auto", marginTop: 0 }}>
                {e.name}: {JSON.stringify(Object.fromEntries(e.attributes.map((a) => [a.key, attrString(e.attributes, a.key)])))}
              </pre>
            ))}
          </div>
        )}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------- Tables

type FileEventData = { path?: string; op?: string; sensitive?: boolean; bytes?: number };
type NetEventData = { host?: string; dst?: string; port?: number; bytes?: number; allowed?: boolean };

const timeCol = {
  key: "ts",
  header: "Time",
  width: pixel(100),
  renderCell: (e: Event) => <span className="mono" style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>{new Date(e.ts).toLocaleTimeString()}</span>,
};

const fileColumns = [
  timeCol,
  { key: "type", header: "Type", width: pixel(110), renderCell: (e: Event) => <span className="mono" style={{ fontSize: 12, color: "var(--color-text-secondary)" }}>{e.type}</span> },
  {
    key: "path",
    header: "Path",
    width: proportional(1, { minWidth: 220 }),
    renderCell: (e: Event) => (
      <span className="mono sbx-truncate" style={{ fontSize: 12.5 }} title={(e.data as FileEventData).path}>
        {(e.data as FileEventData).path ?? "—"}
      </span>
    ),
  },
  {
    key: "op",
    header: "Op",
    width: pixel(90),
    renderCell: (e: Event) => {
      const d = e.data as FileEventData;
      return <Muted>{d.op ?? (d.bytes !== undefined ? `${d.bytes}B` : "—")}</Muted>;
    },
  },
  {
    key: "sensitive",
    header: "Sensitive",
    width: pixel(110),
    renderCell: (e: Event) => ((e.data as FileEventData).sensitive ? <StatusDot tone="warning" label="sensitive" /> : <Muted>—</Muted>),
  },
];

const networkColumns = [
  timeCol,
  {
    key: "type",
    header: "Verdict",
    width: pixel(110),
    renderCell: (e: Event) =>
      e.type === "egress.deny" ? <StatusDot tone="danger" label="deny" /> : <StatusDot tone={e.type === "egress.allow" ? "ready" : "muted"} label={e.type.replace("egress.", "").replace("net.", "")} />,
  },
  {
    key: "host",
    header: "Host / destination",
    width: proportional(1, { minWidth: 200 }),
    renderCell: (e: Event) => (
      <span className="mono sbx-truncate" style={{ fontSize: 12.5 }}>
        {(e.data as NetEventData).host ?? (e.data as NetEventData).dst ?? "—"}
      </span>
    ),
  },
  { key: "port", header: "Port", width: pixel(80), align: "end" as const, renderCell: (e: Event) => <span className="mono" style={{ fontSize: 12.5 }}>{(e.data as NetEventData).port ?? "—"}</span> },
  { key: "bytes", header: "Bytes", width: pixel(90), align: "end" as const, renderCell: (e: Event) => <span className="mono" style={{ fontSize: 12.5 }}>{(e.data as NetEventData).bytes ?? "—"}</span> },
];

const alertColumns = [
  {
    key: "ts",
    header: "Time",
    width: pixel(90),
    renderCell: (e: Event) => <Ago value={e.ts} />,
  },
  { key: "severity", header: "Severity", width: pixel(96), renderCell: (e: Event) => <SeverityTag severity={(e.data as AlertData).severity} /> },
  {
    key: "rule",
    header: "Rule",
    width: pixel(180),
    renderCell: (e: Event) => (
      <span className="mono sbx-truncate" style={{ fontSize: 12 }}>
        {(e.data as AlertData).rule}
      </span>
    ),
  },
  {
    key: "msg",
    header: "Message",
    width: proportional(2, { minWidth: 220 }),
    renderCell: (e: Event) => {
      const msg = (e.data as AlertData).msg;
      return (
        <span title={msg} className="sbx-truncate" style={{ fontSize: 13 }}>
          {msg}
        </span>
      );
    },
  },
];

// ---------------------------------------------------------------- Page

export default function SessionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as TabKey | null) ?? "timeline";
  const highlightToolCall = params.get("tool_call");
  const [selectedSpan, setSelectedSpan] = useState<OtlpSpan | null>(null);

  const setTab = (t: string) =>
    setParams(
      (p) => {
        p.set("tab", t);
        return p;
      },
      { replace: true },
    );

  const detailQuery = useQuery({
    queryKey: ["session", id],
    queryFn: () => api.get<SessionDetailT>(`/api/sessions/${id}`),
    enabled: !!id,
  });
  const eventsQuery = useQuery({
    queryKey: ["session-events", id],
    queryFn: () => api.get<Event[]>(`/api/sessions/${id}/events?limit=1000`),
    enabled: !!id,
  });
  const traceQuery = useQuery({
    queryKey: ["session-trace", id],
    queryFn: () => api.get<OtlpTrace>(`/api/sessions/${id}/trace`),
    enabled: !!id && tab === "trace",
  });
  const processesQuery = useQuery({
    queryKey: ["session-processes", id],
    queryFn: () => api.get<ProcessNode[]>(`/api/sessions/${id}/processes`),
    enabled: !!id && tab === "processes",
  });

  if (!id) return null;

  const events = eventsQuery.data ?? [];
  const fileEvents = events.filter((e) => ["file.read", "file.write", "file.edit", "file.access"].includes(e.type));
  const networkEvents = events.filter((e) => ["net.connect", "egress.allow", "egress.deny"].includes(e.type));
  const alertEvents = events.filter((e) => e.type === "security.alert");

  return (
    <Page title={id} description="Every event, process, file and network call this session produced.">
      <Query query={detailQuery}>
        {(session) => {
          const present = SEVERITIES.filter((s) => session.alerts[s] > 0);
          return (
            <>
              <Card>
                <div className="sbx-stack-24">
                  <KeyValueGrid
                    columns={4}
                    items={[
                      {
                        label: "Started",
                        value: new Date(session.first_ts).toLocaleString(),
                      },
                      {
                        label: "Last activity",
                        value: new Date(session.last_ts).toLocaleString(),
                      },
                      { label: "Duration", value: <span className="mono">{durationLabel(session.first_ts, session.last_ts)}</span> },
                      {
                        label: "Alerts",
                        value:
                          present.length === 0 ? (
                            <StatusDot tone="ready" label="none" />
                          ) : (
                            <span className="sbx-row" style={{ gap: 10 }}>
                              {present.map((s) => (
                                <SeverityTag key={s} severity={s} count={session.alerts[s]} />
                              ))}
                            </span>
                          ),
                      },
                      { label: "Execs", value: <span className="mono">{session.execs}</span> },
                      { label: "Events", value: <span className="mono">{session.events.toLocaleString()}</span> },
                      {
                        label: "Sandboxes",
                        wide: true,
                        value:
                          (session.sandboxes ?? []).length === 0 ? (
                            "—"
                          ) : (
                            <Tags>
                              {(session.sandboxes ?? []).map((sb) => (
                                <Tag key={sb.id} mono to={`/sandboxes/${sb.id}`}>
                                  {sb.id} · {sb.isolation ?? sb.backend}
                                </Tag>
                              ))}
                            </Tags>
                          ),
                      },
                    ]}
                  />
                </div>
              </Card>

              <div className="sbx-stack-24">
                <div className="sbx-tabs">
                  <TabList value={tab} onChange={setTab}>
                    <Tab value="timeline" label={`Timeline ${events.length}`} />
                    <Tab value="trace" label="Trace" />
                    <Tab value="processes" label="Processes" />
                    <Tab value="files" label={`Files ${fileEvents.length}`} />
                    <Tab value="network" label={`Network ${networkEvents.length}`} />
                    <Tab value="alerts" label={`Alerts ${alertEvents.length}`} />
                  </TabList>
                </div>

                {tab === "timeline" && (
                  <Timeline sessionId={id} events={events} isLoading={eventsQuery.isLoading} highlightToolCall={highlightToolCall} />
                )}

                {tab === "trace" && (
                  <Query query={traceQuery}>
                    {(trace) => (
                      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 340px", gap: 24, alignItems: "start" }}>
                        <Card padding="tight">
                          <div style={{ overflowX: "auto" }}>
                            <TraceWaterfall trace={trace} selectedSpanId={selectedSpan?.spanId} onSelect={setSelectedSpan} />
                          </div>
                        </Card>
                        <SpanPanel span={selectedSpan} />
                      </div>
                    )}
                  </Query>
                )}

                {tab === "processes" && (
                  <Query query={processesQuery} empty={<EmptyState title="No process telemetry" description="This session produced no process events." />}>
                    {(roots) => (
                      <div className="sbx-events">
                        {roots.map((r, i) => (
                          <ProcessNodeRow key={`${r.pid}-${i}`} node={r} />
                        ))}
                      </div>
                    )}
                  </Query>
                )}

                {tab === "files" && (
                  <DataTable data={fileEvents} idKey="id" empty="No file activity for this session." columns={fileColumns} />
                )}

                {tab === "network" && (
                  <DataTable data={networkEvents} idKey="id" empty="No network activity for this session." columns={networkColumns} />
                )}

                {tab === "alerts" && (
                  <DataTable
                    data={alertEvents}
                    idKey="id"
                    empty="No alerts for this session."
                    columns={[
                      ...alertColumns,
                      {
                        key: "actions",
                        header: "",
                        width: pixel(120),
                        align: "end" as const,
                        renderCell: (e: Event) =>
                          e.tool_call_id ? (
                            <button
                              type="button"
                              className="sbx-link"
                              style={{ border: "none", background: "transparent", padding: 0, cursor: "pointer", fontSize: 12.5 }}
                              onClick={() =>
                                setParams((p) => {
                                  p.set("tab", "timeline");
                                  p.set("tool_call", e.tool_call_id);
                                  return p;
                                })
                              }
                            >
                              Tool call
                            </button>
                          ) : null,
                      },
                    ]}
                  />
                )}
              </div>
            </>
          );
        }}
      </Query>
    </Page>
  );
}
