import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Button } from "@astryxdesign/core/Button";
import { VStack } from "@astryxdesign/core/Stack";
import { Popover } from "@astryxdesign/core/Popover";
import { Selector } from "@astryxdesign/core/Selector";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Switch } from "@astryxdesign/core/Switch";
import { Page, ErrorState } from "../components/Page";
import { useTableTools, SkeletonTable, sandboxColumns } from "../components/tables";
import { CreateSandboxDrawer } from "../components/CreateSandboxDrawer";
import { useOpenKey } from "../lib/useOpenKey";
import { DataTable, EmptyState, SearchField, Toolbar } from "../ui";
import { api } from "../lib/api";
import { useSessionFilter } from "../lib/sessionFilter";
import { IconPlus, IconSliders } from "../components/icons";
import { RUNTIMES } from "../lib/types";
import type { ApiKey, SandboxInfo, SandboxState } from "../lib/types";

const STATES: SandboxState[] = ["creating", "ready", "busy", "paused", "stopped", "archived", "destroyed"];

type Filters = { state?: string; tier?: string; host?: string; key?: string; labelKey?: string; labelValue?: string };

function FilterPopover({ filters, setFilters, hosts, keys }: { filters: Filters; setFilters: (f: Filters) => void; hosts: string[]; keys: ApiKey[] }) {
  const count = Object.values(filters).filter(Boolean).length;
  return (
    <Popover
      label="Filter"
      width={280}
      content={
        <VStack gap={3}>
          <Selector label="State" options={STATES.map((s) => ({ value: s, label: s }))} value={filters.state ?? null} onChange={(v) => setFilters({ ...filters, state: v ?? undefined })} hasClear placeholder="Any" width="100%" />
          <Selector label="Runtime" options={RUNTIMES.map((t) => ({ value: t.value, label: t.label }))} value={filters.tier ?? null} onChange={(v) => setFilters({ ...filters, tier: v ?? undefined })} hasClear placeholder="Any" width="100%" />
          <Selector label="Host" options={hosts.map((h) => ({ value: h, label: h }))} value={filters.host ?? null} onChange={(v) => setFilters({ ...filters, host: v ?? undefined })} hasClear placeholder="Any" width="100%" />
          <Selector label="Key" options={keys.map((k) => ({ value: k.id, label: k.name }))} value={filters.key ?? null} onChange={(v) => setFilters({ ...filters, key: v ?? undefined })} hasClear placeholder="Any" width="100%" />
          <TextInput label="Label key" size="sm" value={filters.labelKey ?? ""} onChange={(v) => setFilters({ ...filters, labelKey: v || undefined })} placeholder="key" width="100%" />
          <TextInput label="Label value" size="sm" value={filters.labelValue ?? ""} onChange={(v) => setFilters({ ...filters, labelValue: v || undefined })} placeholder="value" width="100%" />
          {count > 0 && <Button label="Clear filters" size="sm" variant="secondary" onClick={() => setFilters({})} />}
        </VStack>
      }
    >
      <Button label={count ? `Filter (${count})` : "Filter"} variant="secondary" icon={<IconSliders width={14} height={14} />} />
    </Popover>
  );
}

export default function SandboxesPage() {
  const { session } = useSessionFilter();
  const navigate = useNavigate();
  const [filters, setFilters] = useState<Filters>({});
  const [createOpen, setCreateOpen] = useState(false);
  const createKey = useOpenKey(createOpen);
  const [showDestroyed, setShowDestroyed] = useState(false);

  const query = useQuery({
    queryKey: ["sandboxes", filters.state],
    queryFn: () => api.get<SandboxInfo[]>(`/api/sandboxes${filters.state ? `?state=${encodeURIComponent(filters.state)}` : ""}`),
    refetchInterval: 5000,
  });

  const hosts = useMemo(() => [...new Set((query.data ?? []).map((sb) => sb.host_id))].sort(), [query.data]);

  // 404s until the control plane grows /api/keys (§4b) — the filter just
  // has nothing to offer until then.
  const keysQuery = useQuery({
    queryKey: ["keys", "filter"],
    queryFn: () => api.get<ApiKey[]>("/api/keys"),
    retry: false,
  });

  const filtered = useMemo(() => {
    let rows = query.data ?? [];
    // A new console shouldn't open onto ~30 dead rows: destroyed sandboxes are hidden
    // by default (an explicit State=destroyed filter or the toggle below overrides this).
    if (!showDestroyed && filters.state !== "destroyed") rows = rows.filter((sb) => sb.state !== "destroyed");
    if (session) rows = rows.filter((sb) => sb.pi_session === session);
    if (filters.tier) rows = rows.filter((sb) => sb.isolation === filters.tier);
    if (filters.host) rows = rows.filter((sb) => sb.host_id === filters.host);
    if (filters.key) rows = rows.filter((sb) => sb.api_key_id === filters.key);
    if (filters.labelKey) {
      rows = rows.filter((sb) => {
        const v = sb.labels?.[filters.labelKey!];
        return filters.labelValue ? v === filters.labelValue : v !== undefined;
      });
    }
    return rows;
  }, [query.data, session, filters, showDestroyed]);

  const table = useTableTools(filtered, {
    search: (row) => `${row.id} ${row.name ?? ""} ${row.template} ${row.workspace_path} ${Object.entries(row.labels ?? {}).map(([k, v]) => `${k}=${v}`).join(" ")}`,
    defaultSort: [{ sortKey: "created_at", direction: "descending" }],
  });

  const columns = sandboxColumns();
  const isEmpty = (query.data ?? []).length === 0 && !filters.state;

  return (
    <Page
      title="Sandboxes"
      description={session ? `Sandboxes acquired by session ${session}.` : "Every sandbox this control plane has created, live and historical."}
      action={<Button label="Create Sandbox" icon={<IconPlus width={16} height={16} />} onClick={() => setCreateOpen(true)} />}
    >
      <div className="sbx-stack-16">
        {!isEmpty && (
          <Toolbar>
            <SearchField value={table.query} onChange={table.setQuery} placeholder="Search by name, id, or label…" />
            <FilterPopover filters={filters} setFilters={setFilters} hosts={hosts} keys={keysQuery.data ?? []} />
            <Switch label="Show destroyed" value={showDestroyed} onChange={setShowDestroyed} />
          </Toolbar>
        )}

        {query.isLoading && <SkeletonTable columns={columns} />}
        {query.error && <ErrorState error={query.error} onRetry={() => query.refetch()} />}
        {query.data && isEmpty && (
          <EmptyState
            title="Spin your next Sandbox"
            description="Run code in an isolated environment in milliseconds."
            actions={
              <>
                <Button label="Create Sandbox" icon={<IconPlus width={16} height={16} />} onClick={() => setCreateOpen(true)} />
                <Button label="Onboarding guide" variant="secondary" onClick={() => navigate("/get-started")} />
              </>
            }
          />
        )}
        {query.data && !isEmpty && (
          <DataTable
            data={table.rows}
            idKey="id"
            plugins={table.plugins}
            empty="No sandboxes match these filters."
            columns={columns}
          />
        )}
      </div>

      <CreateSandboxDrawer key={createKey} isOpen={createOpen} onOpenChange={setCreateOpen} />
    </Page>
  );
}
