import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { proportional, pixel } from "@astryxdesign/core/Table";
import { Tooltip } from "@astryxdesign/core/Tooltip";
import { Page, ErrorState } from "../components/Page";
import { SkeletonTable, IdCell, SeverityTag, Ago, useTableTools } from "../components/tables";
import { DataTable, EmptyState, FilterChip, SearchField, Toolbar } from "../ui";
import { api } from "../lib/api";
import { useSessionFilter } from "../lib/sessionFilter";
import { SEVERITIES } from "../lib/severity";
import type { AlertData, Event, Host, Severity } from "../lib/types";
import { Rules } from "../lib/types";

const columns = [
  {
    key: "ts",
    header: "Time",
    width: pixel(90),
    renderCell: (e: Event) => <Ago value={e.ts} />,
  },
  {
    key: "severity",
    header: "Severity",
    width: pixel(96),
    renderCell: (e: Event) => <SeverityTag severity={(e.data as AlertData).severity} />,
  },
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
  {
    key: "pi_session",
    header: "Session",
    width: proportional(1, { minWidth: 130 }),
    renderCell: (e: Event) => <IdCell id={e.pi_session} to={e.pi_session ? `/sessions/${e.pi_session}` : undefined} />,
  },
  {
    key: "sandbox_id",
    header: "Sandbox",
    width: proportional(1, { minWidth: 120 }),
    renderCell: (e: Event) => <IdCell id={e.sandbox_id} to={e.sandbox_id ? `/sandboxes/${e.sandbox_id}` : undefined} />,
  },
  {
    key: "tool_call_id",
    header: "",
    width: pixel(96),
    align: "end" as const,
    renderCell: (e: Event) =>
      e.tool_call_id ? (
        <Link to={`/sessions/${e.pi_session}?tab=timeline&tool_call=${e.tool_call_id}`} className="sbx-link" style={{ fontSize: 12.5 }}>
          Tool call
        </Link>
      ) : null,
  },
];

export default function AlertsPage() {
  const { session } = useSessionFilter();
  const [severity, setSeverity] = useState<Severity | undefined>();
  const [operational, setOperational] = useState(false);

  const query = useQuery({
    queryKey: ["alerts", "page", session, severity],
    queryFn: () => {
      const params = new URLSearchParams({ limit: "500" });
      if (session) params.set("pi_session", session);
      if (severity) params.set("severity", severity);
      return api.get<Event[]>(`/api/alerts?${params}`);
    },
  });

  // Catalogue description for the "Operational" chip's tooltip — same source
  // the Policy page reads (hosts[].policy.rules), so the wording never drifts.
  const hostsQuery = useQuery({ queryKey: ["hosts", "alerts-catalogue"], queryFn: () => api.get<Host[]>("/api/hosts"), retry: false });
  const operationalDescription = hostsQuery.data
    ?.find((h) => h.policy?.rules?.length)
    ?.policy?.rules?.find((r) => r.rule === Rules.SANDBOX_LONG_RUNNING)?.description;

  const table = useTableTools(query.data, {
    search: (e) => `${(e.data as AlertData).rule} ${(e.data as AlertData).msg} ${e.pi_session} ${e.sandbox_id}`,
    sort: false,
  });
  const rows = operational ? table.rows.filter((e) => (e.data as AlertData).rule === Rules.SANDBOX_LONG_RUNNING) : table.rows;

  return (
    <Page title="Alerts" description={session ? `Alerts raised in session ${session}.` : "Every detection the boundary and the in-sandbox telemetry raised."}>
      <div className="sbx-stack-16">
        <Toolbar
          end={[
            ...SEVERITIES.map((sev) => (
              <FilterChip key={sev} label={sev} isActive={severity === sev} onClick={() => setSeverity(severity === sev ? undefined : sev)} />
            )),
            <Tooltip key="operational" content={operationalDescription ?? "Sandboxes running longer than the operational threshold"}>
              <FilterChip label="Operational" isActive={operational} onClick={() => setOperational((v) => !v)} />
            </Tooltip>,
          ]}
        >
          <SearchField value={table.query} onChange={table.setQuery} placeholder="Search rule, message or session…" />
        </Toolbar>

        {query.isLoading && <SkeletonTable columns={columns} />}
        {query.error && <ErrorState error={query.error} onRetry={() => query.refetch()} />}
        {query.data && query.data.length === 0 && (
          <EmptyState title="No alerts" description="Nothing in the last window tripped a detection rule. The sandbox is clean." />
        )}
        {query.data && query.data.length > 0 && (
          <DataTable data={rows} idKey="id" empty="No alerts match this search." columns={columns} />
        )}
      </div>
    </Page>
  );
}
