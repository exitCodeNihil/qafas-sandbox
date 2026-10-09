import { useQuery } from "@tanstack/react-query";
import { proportional, pixel } from "@astryxdesign/core/Table";
import { Tooltip } from "@astryxdesign/core/Tooltip";
import { Page, ErrorState } from "../components/Page";
import { SkeletonTable, useTableTools, Ago, Muted } from "../components/tables";
import { DataTable, EmptyState, SearchField, Tag, Tags, Toolbar } from "../ui";
import { api } from "../lib/api";
import { runtimeLabel } from "../lib/types";
import type { Host, HostCaps } from "../lib/types";
import { formatMiB } from "../lib/format";

/** Compact chip list from `Host.caps` (v4c: what `qafas doctor` found on the
 * machine) — only what's present/true, so a host with nothing enabled shows "—". */
function capsChips(caps?: HostCaps): string[] {
  if (!caps) return [];
  const chips: string[] = [];
  if (caps.kvm) chips.push("KVM");
  if (caps.firecracker) chips.push("Firecracker");
  if (caps.podman) chips.push("podman");
  if (caps.process_sandbox) chips.push("process sandbox");
  if (caps.bpftrace) chips.push("bpftrace");
  if (caps.hugepages_mib) chips.push(`huge pages ${Math.round(caps.hugepages_mib / 1024)} GiB`);
  if (caps.cpus || caps.mem_mib) chips.push(`${caps.cpus} cpu × ${Math.round(caps.mem_mib / 1024)} GiB`);
  return chips;
}

const columns = [
  {
    key: "id",
    header: "Host",
    width: proportional(1, { minWidth: 130 }),
    sortable: true,
    renderCell: (h: Host) => (
      <span className="mono sbx-truncate" style={{ fontSize: 13 }}>
        {h.id}
      </span>
    ),
  },
  { key: "backend", header: "Backend", width: pixel(110), renderCell: (h: Host) => <Muted>{h.backend}</Muted> },
  {
    key: "tiers",
    header: (
      <Tooltip content="Runtimes are what the daemon is configured to serve within its capabilities (SBX_TIERS).">
        <span>Runtimes</span>
      </Tooltip>
    ),
    width: proportional(1.3, { minWidth: 190 }),
    renderCell: (h: Host) => {
      const tiers = h.tiers ?? [];
      const extra = (h.caps?.supported ?? []).filter((s) => !tiers.includes(s));
      return (
        <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          {tiers.length === 0 ? (
            <Muted>—</Muted>
          ) : (
            <Tags nowrap>
              {tiers.map((t) => (
                <Tag key={t} title={t}>{runtimeLabel(t)}</Tag>
              ))}
            </Tags>
          )}
          {extra.length > 0 && <Muted>{`could also serve: ${extra.map((t) => runtimeLabel(t)).join(", ")}`}</Muted>}
        </div>
      );
    },
  },
  {
    key: "committed",
    header: (
      <Tooltip content="Σ limits of live sandboxes on this host vs its capabilities (§3a v5).">
        <span>Committed</span>
      </Tooltip>
    ),
    width: pixel(170),
    renderCell: (h: Host) => {
      const c = h.committed;
      const caps = h.caps;
      if (!c || !caps || (!caps.cpus && !caps.mem_mib)) return <Muted>—</Muted>;
      const cpuPct = caps.cpus ? (c.cpus / caps.cpus) * 100 : 0;
      const memPct = caps.mem_mib ? (c.mem_mib / caps.mem_mib) * 100 : 0;
      const line = (label: string, pct: number) => (
        <>
          <span className="mono sbx-truncate" style={{ fontSize: 11.5, color: "var(--color-text-secondary)" }}>
            {label}
          </span>
          <div className="sbx-committed-bar">
            <span className="sbx-committed-fill" data-warn={pct >= 90} style={{ width: `${Math.min(100, pct)}%` }} />
          </div>
        </>
      );
      return (
        <div className="sbx-committed">
          {line(`${c.cpus} / ${caps.cpus} cpu`, cpuPct)}
          {line(`${formatMiB(c.mem_mib)} / ${formatMiB(caps.mem_mib)}`, memPct)}
        </div>
      );
    },
  },
  {
    key: "caps",
    header: "Capabilities",
    width: proportional(1.8, { minWidth: 240 }),
    renderCell: (h: Host) => {
      const chips = capsChips(h.caps);
      return chips.length === 0 ? (
        <Muted>—</Muted>
      ) : (
        <Tags>
          {chips.map((c) => (
            <Tag key={c}>{c}</Tag>
          ))}
        </Tags>
      );
    },
  },
  {
    key: "url",
    header: "Endpoint",
    width: proportional(1.2, { minWidth: 160 }),
    renderCell: (h: Host) => (
      <span className="mono sbx-truncate" style={{ fontSize: 12, color: "var(--color-text-secondary)" }} title={h.url}>
        {h.url}
      </span>
    ),
  },
  {
    key: "pool",
    header: "Pool warm / target",
    width: proportional(1, { minWidth: 160 }),
    renderCell: (h: Host) => {
      const summary = Object.entries(h.pool)
        .map(([key, val]) => `${key}: ${val.warm}/${val.target}`)
        .join(" · ");
      return summary ? (
        <span className="mono sbx-truncate" style={{ fontSize: 12 }} title={summary}>
          {summary}
        </span>
      ) : (
        <Muted>—</Muted>
      );
    },
  },
  {
    key: "last_seen",
    header: "Last seen",
    width: pixel(96),
    sortable: true,
    renderCell: (h: Host) => <Ago value={h.last_seen} />,
  },
];

export default function HostsPage() {
  const query = useQuery({
    queryKey: ["hosts"],
    queryFn: () => api.get<Host[]>("/api/hosts"),
  });
  const table = useTableTools(query.data, { search: (h) => `${h.id} ${h.backend} ${h.url}` });

  return (
    <Page title="Hosts" description="The qafas daemons this control plane places sandboxes on.">
      <div className="sbx-stack-16">
        <Toolbar>
          <SearchField value={table.query} onChange={table.setQuery} placeholder="Search hosts…" />
        </Toolbar>

        {query.isLoading && <SkeletonTable columns={columns} />}
        {query.error && <ErrorState error={query.error} onRetry={() => query.refetch()} />}
        {query.data && query.data.length === 0 && (
          <EmptyState title="No hosts registered" description="A qafas host registers itself with the control plane on startup." />
        )}
        {query.data && query.data.length > 0 && (
          <DataTable data={table.rows} idKey="id" plugins={table.plugins} empty="No hosts match this search." columns={columns} textOverflow="wrap" />
        )}
      </div>
    </Page>
  );
}
