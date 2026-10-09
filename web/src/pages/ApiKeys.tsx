import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { proportional, pixel } from "@astryxdesign/core/Table";
import { Button } from "@astryxdesign/core/Button";
import { MoreMenu } from "@astryxdesign/core/MoreMenu";
import { useImperativeAlertDialog } from "@astryxdesign/core/AlertDialog";
import { Page, ErrorState } from "../components/Page";
import { useTableTools, SkeletonTable, MutedCell, Ago } from "../components/tables";
import { CreateApiKeyDrawer } from "../components/CreateApiKeyDrawer";
import { DataTable, EmptyState, SearchField, StatusDot, Tag, Tags, Toolbar } from "../ui";
import { api, ApiError } from "../lib/api";
import { limitsSummary, keyPrefixLabel } from "../lib/apiKeys";
import { IconPlus, IconRequests, IconTrash } from "../components/icons";
import type { ApiKey } from "../lib/types";

export default function ApiKeysPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const alertDialog = useImperativeAlertDialog();
  const [params, setParams] = useSearchParams();
  const [createOpen, setCreateOpen] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  // "Create an API key" link from Get Started opens straight into the drawer.
  useEffect(() => {
    if (params.get("create") === "1") {
      setCreateOpen(true);
      setParams((p) => {
        p.delete("create");
        return p;
      }, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const query = useQuery({
    queryKey: ["keys"],
    queryFn: () => api.get<ApiKey[]>("/api/keys"),
    retry: false,
  });

  // Active keys first (newest first), revoked ones after (also newest
  // first) — this is the whole sort, so the generic column-sort plugin is
  // skipped rather than fought.
  const sorted = useMemo(() => {
    const rows = [...(query.data ?? [])];
    rows.sort((a, b) => {
      const revokedDiff = Number(!!a.revoked_at) - Number(!!b.revoked_at);
      if (revokedDiff !== 0) return revokedDiff;
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });
    return rows;
  }, [query.data]);

  const table = useTableTools(sorted, {
    search: (row) => `${row.name} ${row.prefix} ${row.scopes.join(" ")}`,
    sort: false,
  });

  const confirmRevoke = (key: ApiKey) => {
    alertDialog.show({
      title: `Revoke ${key.name}?`,
      description: "Sandboxes it already created keep running. New requests with this key get 401. The key stays listed as revoked until deleted.",
      actionLabel: "Revoke",
      onAction: async () => {
        setRevokeError(null);
        try {
          await api.del(`/api/keys/${key.id}`);
          void qc.invalidateQueries({ queryKey: ["keys"] });
        } catch (err) {
          setRevokeError(err instanceof ApiError ? `${key.name}: ${err.message}` : `${key.name}: revoke failed`);
        }
        alertDialog.hide();
      },
    });
  };

  // A second DELETE on an already-revoked key hard-deletes it (the API's two-step
  // semantics — see ApiKeys revoke/delete). Only ever offered on a revoked row.
  const confirmDelete = (key: ApiKey) => {
    alertDialog.show({
      title: `Delete ${key.name}?`,
      description: "Permanently removes this revoked key from the list. This cannot be undone.",
      actionLabel: "Delete",
      onAction: async () => {
        setRevokeError(null);
        try {
          await api.del(`/api/keys/${key.id}`);
          void qc.invalidateQueries({ queryKey: ["keys"] });
        } catch (err) {
          setRevokeError(err instanceof ApiError ? `${key.name}: ${err.message}` : `${key.name}: delete failed`);
        }
        alertDialog.hide();
      },
    });
  };

  const columns = [
    {
      key: "name",
      header: "Name",
      width: proportional(1.2, { minWidth: 160 }),
      renderCell: (k: ApiKey) => (
        <MutedCell muted={!!k.revoked_at}>
          <span className="sbx-truncate" style={{ fontSize: 13 }}>
            {k.name}
          </span>
        </MutedCell>
      ),
    },
    {
      key: "status",
      header: "Status",
      width: pixel(96),
      renderCell: (k: ApiKey) => (k.revoked_at ? <StatusDot tone="muted" label="revoked" muted /> : <StatusDot tone="ready" label="active" />),
    },
    {
      key: "prefix",
      header: "Prefix",
      width: pixel(140),
      renderCell: (k: ApiKey) => {
        const label = keyPrefixLabel(k.prefix);
        return (
          <MutedCell muted={!!k.revoked_at}>
            <span className="mono sbx-truncate" title={label} style={{ fontSize: 12 }}>
              {label}
            </span>
          </MutedCell>
        );
      },
    },
    {
      key: "scopes",
      header: "Scopes",
      width: pixel(130),
      renderCell: (k: ApiKey) => (
        <Tags nowrap>
          {k.scopes.map((s) => (
            <Tag key={s} tone={s === "admin" ? "warning" : undefined}>
              {s}
            </Tag>
          ))}
        </Tags>
      ),
    },
    {
      key: "limits",
      header: "Limits",
      width: proportional(1.2, { minWidth: 180 }),
      renderCell: (k: ApiKey) => {
        const summary = limitsSummary(k.limits);
        return (
          <span className="sbx-truncate" title={summary} style={{ fontSize: 12.5, color: "var(--color-text-secondary)" }}>
            {summary}
          </span>
        );
      },
    },
    { key: "live_sandboxes", header: "Live", width: pixel(64), align: "end" as const, renderCell: (k: ApiKey) => <span className="mono" style={{ fontSize: 12.5 }}>{k.live_sandboxes}</span> },
    { key: "created_24h", header: "New 24h", width: pixel(84), align: "end" as const, renderCell: (k: ApiKey) => <span className="mono" style={{ fontSize: 12.5 }}>{k.created_24h}</span> },
    {
      key: "last_used_at",
      header: "Last used",
      width: pixel(92),
      renderCell: (k: ApiKey) => (k.last_used_at ? <Ago value={k.last_used_at} /> : <span className="sbx-ago">never</span>),
    },
    {
      key: "created_at",
      header: "Created",
      width: pixel(88),
      renderCell: (k: ApiKey) => <Ago value={k.created_at} />,
    },
    {
      key: "actions",
      header: "",
      width: pixel(72),
      align: "end" as const,
      resizable: false,
      renderCell: (k: ApiKey) => (
        <MoreMenu
          label={`Actions for ${k.name}`}
          items={[
            { label: "Usage", icon: IconRequests, onClick: () => navigate(`/keys/${k.id}`) },
            { type: "divider" as const },
            k.revoked_at
              ? { label: "Delete", icon: IconTrash, onClick: () => confirmDelete(k) }
              : { label: "Revoke", icon: IconTrash, onClick: () => confirmRevoke(k) },
          ]}
        />
      ),
    },
  ];

  return (
    <Page
      title="API Keys"
      description="Scoped credentials the SDK and the pi harness acquire sandboxes with."
      action={<Button label="Create API key" icon={<IconPlus width={16} height={16} />} onClick={() => setCreateOpen(true)} />}
    >
      <div className="sbx-stack-16">
        {revokeError && <ErrorState error={new Error(revokeError)} onRetry={() => setRevokeError(null)} />}

        {(query.data ?? []).length > 0 && (
          <Toolbar>
            <SearchField value={table.query} onChange={table.setQuery} placeholder="Search by name or prefix…" />
          </Toolbar>
        )}

        {query.isLoading && <SkeletonTable columns={columns} />}
        {query.error && <ErrorState error={query.error} onRetry={() => query.refetch()} />}
        {query.data && query.data.length === 0 && (
          <EmptyState
            title="No API keys yet"
            description="Scope a key to what it may do — create sandboxes, set limits — and hand it to the SDK or the harness."
            actions={<Button label="Create API key" icon={<IconPlus width={16} height={16} />} onClick={() => setCreateOpen(true)} />}
          />
        )}
        {query.data && query.data.length > 0 && (
          <DataTable data={table.rows} idKey="id" plugins={table.plugins} empty="No keys match this search." columns={columns} />
        )}
      </div>
      {alertDialog.element}

      <CreateApiKeyDrawer isOpen={createOpen} onOpenChange={setCreateOpen} />
    </Page>
  );
}
