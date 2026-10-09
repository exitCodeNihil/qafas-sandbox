import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { proportional, pixel } from "@astryxdesign/core/Table";
import { Button } from "@astryxdesign/core/Button";
import { MoreMenu } from "@astryxdesign/core/MoreMenu";
import { Spinner } from "@astryxdesign/core/Spinner";
import { Tooltip } from "@astryxdesign/core/Tooltip";
import { useToast } from "@astryxdesign/core/Toast";
import { useImperativeAlertDialog } from "@astryxdesign/core/AlertDialog";
import { Page, ErrorState } from "../components/Page";
import { useTableTools, SkeletonTable, Ago, Muted } from "../components/tables";
import { CreateSnapshotDrawer } from "../components/CreateSnapshotDrawer";
import { CreateSandboxDrawer } from "../components/CreateSandboxDrawer";
import { SecurityCell, kindLabel, sourceLabel, stateTone } from "../components/templates";
import { useOpenKey } from "../lib/useOpenKey";
import { DataTable, EmptyState, SearchField, StatusDot, Tags, Toolbar } from "../ui";
import { api, ApiError } from "../lib/api";
import { IconPlus, IconCube, IconTrash, IconShield, IconSearch } from "../components/icons";
import { runtimeLabel } from "../lib/types";
import type { SnapshotInfo } from "../lib/types";

/** `GET /api/snapshots` rows, one per (host, name) — grouped so the table
 * shows one row per template name with a chip per host that holds it. warm/warm_ready/
 * memory_snapshot/runtime are set identically on every host by the create/PUT fan-out, so
 * the group just carries the first row's values. */
type SnapshotGroup = {
  name: string;
  kind: string;
  runtime?: string;
  source: SnapshotInfo["source"];
  created_at: string;
  rows: SnapshotInfo[];
  warm: number;
  warmReady: number;
  memorySnapshot: boolean;
};

/** A group's overall state for the visible State column — worst-first: any host still
 * building or errored outranks a fully active group. */
function groupState(rows: SnapshotInfo[]): SnapshotInfo["state"] {
  if (rows.some((r) => r.state === "error")) return "error";
  if (rows.some((r) => r.state === "building")) return "building";
  return "active";
}

function groupByName(rows: SnapshotInfo[]): SnapshotGroup[] {
  const byName = new Map<string, SnapshotGroup>();
  for (const r of rows) {
    const g = byName.get(r.name) ?? {
      name: r.name, kind: r.kind, runtime: r.runtime, source: r.source, created_at: r.created_at, rows: [],
      warm: r.warm ?? 0, warmReady: r.warm_ready ?? 0, memorySnapshot: r.memory_snapshot ?? false,
    };
    g.rows.push(r);
    if (new Date(r.created_at).getTime() < new Date(g.created_at).getTime()) g.created_at = r.created_at;
    byName.set(r.name, g);
  }
  return [...byName.values()];
}

function HostsCell({ rows }: { rows: SnapshotInfo[] }) {
  return (
    <Tags>
      {rows.map((r) => (
        <Tooltip key={r.host_id ?? r.name} content={r.state === "error" ? r.error || "build failed" : r.state}>
          <span className="sbx-row" style={{ gap: 4 }}>
            {r.state === "building" && <Spinner size="sm" />}
            <StatusDot tone={stateTone[r.state]} label={r.host_id ?? "—"} />
          </span>
        </Tooltip>
      ))}
    </Tags>
  );
}

export default function SnapshotsPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const alertDialog = useImperativeAlertDialog();
  const [createOpen, setCreateOpen] = useState(false);
  const [sandboxDrawerFor, setSandboxDrawerFor] = useState<string | null>(null);
  const sandboxKey = useOpenKey(!!sandboxDrawerFor);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["snapshots"],
    queryFn: () => api.get<SnapshotInfo[]>("/api/snapshots"),
    refetchInterval: (q) => ((q.state.data ?? []).some((s) => s.state === "building") ? 3000 : 5000),
    retry: false,
  });

  const groups = useMemo(() => groupByName(query.data ?? []), [query.data]);

  const table = useTableTools(groups, {
    search: (row) => `${row.name} ${row.kind} ${runtimeLabel(row.runtime)} ${sourceLabel(row)} ${row.rows.map((r) => r.host_id ?? "").join(" ")}`,
    defaultSort: [{ sortKey: "created_at", direction: "descending" }],
  });

  const toast = useToast();
  const rescan = async (name: string) => {
    try {
      await api.post(`/api/snapshots/${name}/scan`);
      toast({ body: `Scanning ${name}; the grade updates when it finishes.` });
      setTimeout(() => void qc.invalidateQueries({ queryKey: ["snapshots"] }), 8000);
    } catch (err) {
      toast({ body: err instanceof Error ? `Rescan: ${err.message}` : "Rescan failed", type: "error" });
    }
  };

  const confirmDelete = (sn: SnapshotGroup) => {
    alertDialog.show({
      title: `Delete ${sn.name}?`,
      description: "Fails if a live sandbox still uses this as its template. This cannot be undone.",
      actionLabel: "Delete",
      onAction: async () => {
        setDeleteError(null);
        try {
          await api.del(`/api/snapshots/${sn.name}`);
          void qc.invalidateQueries({ queryKey: ["snapshots"] });
        } catch (err) {
          setDeleteError(err instanceof ApiError ? `${sn.name}: ${err.message}` : `${sn.name}: delete failed`);
        }
        alertDialog.hide();
      },
    });
  };

  // Fits a laptop viewport without a sideways scroll: source and kind ride under the
  // name and runtime; warm pools and full security results live on the detail page.
  const columns = [
    {
      key: "name",
      header: "Name",
      width: proportional(2, { minWidth: 170 }),
      sortable: true,
      // State rides on the name: a dot always, a word only when it is not `active`.
      renderCell: (sn: SnapshotGroup) => {
        const st = groupState(sn.rows);
        return (
          <div style={{ minWidth: 0 }}>
            <span className="sbx-row" style={{ gap: 6, minWidth: 0 }}>
              <StatusDot tone={stateTone[st]} label={st === "active" ? undefined : <Muted>{st}</Muted>} />
              <Link to={`/snapshots/${encodeURIComponent(sn.name)}`} className="mono sbx-link sbx-truncate" style={{ fontSize: 13 }}>
                {sn.name}
              </Link>
            </span>
            <span className="mono sbx-truncate" style={{ fontSize: 11.5, display: "block", paddingLeft: 14 }}>
              <Muted>{sourceLabel(sn)}</Muted>
            </span>
          </div>
        );
      },
    },
    {
      key: "runtime",
      header: "Runtime",
      width: proportional(1.2, { minWidth: 130 }),
      renderCell: (sn: SnapshotGroup) => (
        <div>
          <div style={{ fontSize: 13 }}>{[...new Set(sn.rows.map((r) => runtimeLabel(r.runtime)))].join(", ")}</div>
          <Muted>{kindLabel(sn.kind)}</Muted>
        </div>
      ),
    },
    {
      key: "security",
      header: "Security",
      width: pixel(116),
      renderCell: (sn: SnapshotGroup) => <SecurityCell rows={sn.rows} />,
    },
    {
      key: "hosts",
      header: "Hosts",
      width: proportional(1, { minWidth: 100 }),
      renderCell: (sn: SnapshotGroup) => <HostsCell rows={sn.rows} />,
    },
    {
      key: "created_at",
      header: "Created",
      width: pixel(84),
      sortable: true,
      renderCell: (sn: SnapshotGroup) => <Ago value={sn.created_at} />,
    },
    {
      key: "actions",
      header: "",
      width: pixel(52),
      align: "end" as const,
      resizable: false,
      renderCell: (sn: SnapshotGroup) => (
        <MoreMenu
          label={`Actions for ${sn.name}`}
          items={[
            { label: "View details", icon: IconSearch, onClick: () => navigate(`/snapshots/${encodeURIComponent(sn.name)}`) },
            {
              label: "New sandbox from this",
              icon: IconCube,
              isDisabled: !sn.rows.some((r) => r.state === "active"),
              onClick: () => setSandboxDrawerFor(sn.name),
            },
            {
              label: "Rescan security",
              icon: IconShield,
              isDisabled: !sn.rows.some((r) => r.state === "active"),
              onClick: () => void rescan(sn.name),
            },
            { type: "divider" as const },
            { label: "Delete", icon: IconTrash, onClick: () => confirmDelete(sn) },
          ]}
        />
      ),
    },
  ];

  return (
    <Page
      title="Templates"
      description="Images and checkpoints that sandboxes are created from, per runtime."
      action={<Button label="Create Template" icon={<IconPlus width={16} height={16} />} onClick={() => setCreateOpen(true)} />}
    >
      <div className="sbx-stack-16">
        {deleteError && <ErrorState error={new Error(deleteError)} onRetry={() => setDeleteError(null)} />}

        {groups.length > 0 && (
          <Toolbar>
            <SearchField value={table.query} onChange={table.setQuery} placeholder="Search by name, runtime, or source…" />
          </Toolbar>
        )}

        {query.isLoading && <SkeletonTable columns={columns} />}
        {query.error && <ErrorState error={query.error} onRetry={() => query.refetch()} />}
        {query.data && groups.length === 0 && (
          <EmptyState
            title="No templates yet"
            description="Build one from an image reference, a Dockerfile, or a live sandbox and every new sandbox starts from it."
            actions={<Button label="Create Template" icon={<IconPlus width={16} height={16} />} onClick={() => setCreateOpen(true)} />}
          />
        )}
        {query.data && groups.length > 0 && (
          <DataTable data={table.rows} idKey="name" plugins={table.plugins} empty="No templates match this search." columns={columns} textOverflow="wrap" />
        )}
      </div>
      {alertDialog.element}

      <CreateSnapshotDrawer isOpen={createOpen} onOpenChange={setCreateOpen} />
      <CreateSandboxDrawer
        key={sandboxKey}
        isOpen={!!sandboxDrawerFor}
        onOpenChange={(o) => !o && setSandboxDrawerFor(null)}
        prefillSnapshot={sandboxDrawerFor ?? undefined}
      />
    </Page>
  );
}
