import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { proportional, pixel } from "@astryxdesign/core/Table";
import { Page, ErrorState } from "../components/Page";
import { useTableTools, SkeletonTable, IdCell, SeverityCluster, alertsComparator, Ago, Muted } from "../components/tables";
import { DataTable, EmptyState, SearchField, Toolbar } from "../ui";
import { api } from "../lib/api";
import { durationLabel } from "../lib/format";
import type { SessionRow } from "../lib/types";

const columns = [
  {
    key: "pi_session",
    header: "Session",
    width: proportional(2, { minWidth: 180 }),
    sortable: true,
    renderCell: (s: SessionRow) => <IdCell id={s.pi_session} to={`/sessions/${s.pi_session}`} />,
  },
  {
    key: "first_ts",
    header: "Started",
    width: pixel(96),
    sortable: true,
    renderCell: (s: SessionRow) => <Ago value={s.first_ts} />,
  },
  {
    key: "duration",
    header: "Duration",
    width: pixel(90),
    align: "end" as const,
    renderCell: (s: SessionRow) => <span className="mono" style={{ fontSize: 12.5 }}>{durationLabel(s.first_ts, s.last_ts)}</span>,
  },
  {
    key: "sandbox_ids",
    header: "Sandboxes",
    width: proportional(1.4, { minWidth: 140 }),
    renderCell: (s: SessionRow) => (
      <span className="mono sbx-truncate" style={{ fontSize: 12, color: "var(--color-text-secondary)" }} title={s.sandbox_ids.join(", ")}>
        {s.sandbox_ids.length ? s.sandbox_ids.join(", ") : "—"}
      </span>
    ),
  },
  {
    key: "execs",
    header: "Execs",
    width: pixel(72),
    align: "end" as const,
    sortable: true,
    renderCell: (s: SessionRow) => <span className="mono" style={{ fontSize: 12.5 }}>{s.execs}</span>,
  },
  {
    key: "api_key_name",
    header: "Key",
    width: pixel(110),
    renderCell: (s: SessionRow) =>
      s.api_key_name ? (
        <Link to={`/keys/${s.api_key_id}`} className="sbx-link sbx-truncate" style={{ fontSize: 12.5 }}>
          {s.api_key_name}
        </Link>
      ) : (
        <Muted>admin</Muted>
      ),
  },
  {
    key: "alerts",
    header: "Alerts",
    width: pixel(280),
    sortable: true,
    renderCell: (s: SessionRow) => <SeverityCluster alerts={s.alerts} />,
  },
];

export default function SessionsPage() {
  const query = useQuery({
    queryKey: ["sessions"],
    queryFn: () => api.get<SessionRow[]>("/api/sessions?limit=200"),
  });

  const table = useTableTools(query.data, {
    search: (row) => `${row.pi_session} ${row.sandbox_ids.join(" ")} ${row.hosts.join(" ")}`,
    defaultSort: [{ sortKey: "first_ts", direction: "descending" }],
    comparators: { alerts: alertsComparator },
  });

  return (
    <Page title="Sessions" description="Every harness session that has touched a sandbox.">
      <div className="sbx-stack-16">
        <Toolbar>
          <SearchField value={table.query} onChange={table.setQuery} placeholder="Search by session, sandbox or host…" />
        </Toolbar>

        {query.isLoading && <SkeletonTable columns={columns} />}
        {query.error && <ErrorState error={query.error} onRetry={() => query.refetch()} />}
        {query.data && query.data.length === 0 && (
          <EmptyState title="No sessions yet" description="Start one with the harness and it will show up here within a second." />
        )}
        {query.data && query.data.length > 0 && (
          <DataTable
            data={table.rows}
            idKey="pi_session"
            plugins={table.plugins}
            empty="No sessions match this search."
            columns={columns}
          />
        )}
      </div>
    </Page>
  );
}
