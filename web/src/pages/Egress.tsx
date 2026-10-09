import { useQuery } from "@tanstack/react-query";
import { proportional, pixel } from "@astryxdesign/core/Table";
import { Page, ErrorState } from "../components/Page";
import { useTableTools, SkeletonTable, IdCell, Ago, Muted } from "../components/tables";
import { DataTable, EmptyState, SearchField, StatusDot, Toolbar } from "../ui";
import { api } from "../lib/api";
import { useSessionFilter } from "../lib/sessionFilter";
import type { Event } from "../lib/types";

type EgressData = { host?: string; port?: number; bytes?: number; reason?: string };

const columns = [
  {
    key: "ts",
    header: "Time",
    width: pixel(90),
    sortable: true,
    renderCell: (e: Event) => <Ago value={e.ts} />,
  },
  {
    key: "type",
    header: "Verdict",
    width: pixel(96),
    renderCell: (e: Event) =>
      e.type === "egress.deny" ? <StatusDot tone="danger" label="Deny" /> : <StatusDot tone="ready" label="Allow" />,
  },
  {
    key: "host",
    header: "Host",
    width: proportional(1.4, { minWidth: 160 }),
    renderCell: (e: Event) => (
      <span className="mono sbx-truncate" style={{ fontSize: 12.5 }}>
        {(e.data as EgressData).host ?? "—"}
      </span>
    ),
  },
  {
    key: "port",
    header: "Port",
    width: pixel(70),
    align: "end" as const,
    renderCell: (e: Event) => <span className="mono" style={{ fontSize: 12.5 }}>{(e.data as EgressData).port ?? "—"}</span>,
  },
  {
    key: "bytes",
    header: "Bytes",
    width: pixel(90),
    align: "end" as const,
    renderCell: (e: Event) => <span className="mono" style={{ fontSize: 12.5 }}>{(e.data as EgressData).bytes ?? "—"}</span>,
  },
  {
    key: "reason",
    header: "Reason",
    width: proportional(1.2, { minWidth: 140 }),
    renderCell: (e: Event) => <Muted>{(e.data as EgressData).reason ?? "—"}</Muted>,
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
    width: proportional(1, { minWidth: 130 }),
    renderCell: (e: Event) => <IdCell id={e.sandbox_id} to={e.sandbox_id ? `/sandboxes/${e.sandbox_id}` : undefined} />,
  },
];

export default function EgressPage() {
  const { session } = useSessionFilter();
  const query = useQuery({
    queryKey: ["egress"],
    queryFn: () => api.get<Event[]>("/api/egress?limit=500"),
  });

  const scoped = session ? (query.data ?? []).filter((e) => e.pi_session === session) : query.data;
  const table = useTableTools(scoped, {
    search: (row) => {
      const data = row.data as EgressData;
      return `${row.sandbox_id} ${data.host ?? ""} ${data.port ?? ""} ${data.reason ?? ""}`;
    },
    defaultSort: [{ sortKey: "ts", direction: "descending" }],
  });

  return (
    <Page
      title="Egress"
      description={
        session
          ? `Allow and deny decisions the proxy made for session ${session}.`
          : "Every allow and deny decision the egress proxy made at the boundary."
      }
    >
      <div className="sbx-stack-16">
        <Toolbar>
          <SearchField value={table.query} onChange={table.setQuery} placeholder="Search host, port or sandbox…" />
        </Toolbar>

        {query.isLoading && <SkeletonTable columns={columns} />}
        {query.error && <ErrorState error={query.error} onRetry={() => query.refetch()} />}
        {query.data && (scoped ?? []).length === 0 && (
          <EmptyState title="No egress events" description="Nothing has left a sandbox through the proxy in this window." />
        )}
        {query.data && (scoped ?? []).length > 0 && (
          <DataTable data={table.rows} idKey="id" plugins={table.plugins} empty="No egress events match this search." columns={columns} />
        )}
      </div>
    </Page>
  );
}
