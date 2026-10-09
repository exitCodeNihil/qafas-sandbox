import { useMemo, useState, type ReactNode } from "react";
import { proportional, pixel, useTableSortable, useTableSortableState } from "@astryxdesign/core/Table";
import type { TableColumn, TableSortComparator } from "@astryxdesign/core/Table";
import type { TablePlugin, TableSortState } from "@astryxdesign/core/Table";
import { Skeleton } from "@astryxdesign/core/Skeleton";
import { Tooltip } from "@astryxdesign/core/Tooltip";
import { Link } from "react-router-dom";
import { SandboxRowMenu } from "./SandboxRowMenu";
import { SEVERITIES, SEVERITY_ABBR, alertsTotal, severityColor } from "../lib/severity";
import { timeAgo, formatBytes } from "../lib/format";
import { stateTone, timerLabel } from "../lib/sandboxActions";
import { DataTable, StatusDot, Tag, Tags } from "../ui";
import { runtimeLabel } from "../lib/types";
import type { Severity, SandboxInfo } from "../lib/types";

/**
 * Search + click-to-sort for every list page, so each table behaves the same
 * way. Search is a substring match over whatever `search` renders for a row;
 * sorting comes from the design system's plugin and columns opt in with
 * `sortable: true`. `comparators` lets a column sort by a derived value (e.g.
 * total alert count) instead of a raw field.
 */
export function useTableTools<T extends Record<string, unknown>>(
  data: T[] | undefined,
  opts: {
    search: (row: T) => string;
    defaultSort?: TableSortState;
    sort?: boolean;
    comparators?: Partial<Record<string, TableSortComparator<T>>>;
  },
) {
  const [query, setQuery] = useState("");
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const all = data ?? [];
    return q ? all.filter((r) => opts.search(r).toLowerCase().includes(q)) : all;
    // opts.search is a stable module-level function on every page
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, query]);
  const sortable = useTableSortableState<T>({
    data: filtered,
    defaultSort: opts.defaultSort,
    comparators: opts.comparators,
    allowUnsortedState: true,
  });
  const plugin = useTableSortable<T>(sortable.sortConfig);
  const plugins: Record<string, TablePlugin<T>> = opts.sort === false ? {} : { sortable: plugin };
  return {
    query,
    setQuery,
    rows: opts.sort === false ? filtered : sortable.sortedData,
    plugins,
    total: (data ?? []).length,
  };
}

/**
 * Monospace id, truncated with an ellipsis (full id in the native title),
 * optionally linking to a detail page. Used for every id-shaped column so a
 * long id never breaks a row's height.
 */
export function IdCell({ id, to }: { id: string; to?: string }) {
  if (!id) return <Muted>—</Muted>;
  const style = { fontSize: 12, display: "block", minWidth: 0 } as const;
  return to ? (
    <Link to={to} className="mono sbx-truncate sbx-link" title={id} style={style}>
      {id}
    </Link>
  ) : (
    <span className="mono sbx-truncate" title={id} style={{ ...style, color: "var(--color-text-secondary)" }}>
      {id}
    </span>
  );
}

export function Muted({ children }: { children: ReactNode }) {
  return <span style={{ fontSize: 12.5, color: "var(--color-text-secondary)" }}>{children}</span>;
}

/** Compact relative time for a dense row — "12m ago", never wrapped, with
 * the absolute timestamp in the native tooltip. */
export function Ago({ value }: { value?: string | null }) {
  if (!value) return <Muted>—</Muted>;
  return (
    <span className="sbx-ago" title={new Date(value).toLocaleString()}>
      {timeAgo(value)}
    </span>
  );
}

/** Sandbox lifecycle state as a dot + word, never a filled pill. */
export function StateCell({ state }: { state: SandboxInfo["state"] }) {
  return <StatusDot tone={stateTone[state]} label={state} muted={state === "destroyed" || state === "archived"} />;
}

/** One alert severity as a dot + text; only `critical` is filled. */
export function SeverityTag({ severity, count }: { severity: Severity; count?: number }) {
  const label = count === undefined ? severity : `${count} ${SEVERITY_ABBR[severity]}`;
  if (severity === "critical") return <span className="sbx-sev sbx-sev-critical">{label}</span>;
  return (
    <span className="sbx-sev">
      <span className="sbx-status-dot" style={{ ["--dot" as string]: severityColor(severity) }} />
      {label}
    </span>
  );
}

/**
 * Compact single-line alert summary — "2 crit · 7 med" with a colored dot
 * per severity — instead of a badge cluster that wraps into a ragged grid.
 */
export function SeverityCluster({ alerts, maxWidth = 248 }: { alerts: Record<Severity, number>; maxWidth?: number }) {
  const present = SEVERITIES.filter((s) => alerts[s] > 0);
  if (present.length === 0) return <Muted>none</Muted>;
  return (
    <Tooltip content={present.map((s) => `${alerts[s]} ${s}`).join(", ")}>
      <span
        className="sbx-row"
        style={{ gap: 8, whiteSpace: "nowrap", overflow: "hidden", maxWidth, display: "inline-flex" }}
      >
        {present.map((s) => (
          <SeverityTag key={s} severity={s} count={alerts[s]} />
        ))}
      </span>
    </Tooltip>
  );
}

/** Shared sort comparator: total alert count, weighted so severity ranks first. */
export const alertsComparator = <T extends { alerts: Record<Severity, number> }>(a: T, b: T) =>
  alertsTotal(a.alerts) - alertsTotal(b.alerts);

/** `key=value` label tags with a "+n" overflow. */
export function LabelChips({ labels, max = 2 }: { labels: Record<string, string> | undefined; max?: number }) {
  const entries = Object.entries(labels ?? {});
  if (entries.length === 0) return <Muted>—</Muted>;
  const shown = entries.slice(0, max);
  const rest = entries.slice(max);
  return (
    <Tags nowrap>
      {shown.map(([k, v]) => (
        <Tag key={k} mono title={`${k}=${v}`}>{`${k}=${v}`}</Tag>
      ))}
      {rest.length > 0 && (
        <Tooltip content={rest.map(([k, v]) => `${k}=${v}`).join(", ")}>
          <Tag>{`+${rest.length}`}</Tag>
        </Tooltip>
      )}
    </Tags>
  );
}

/**
 * Loading placeholder: same columns (so widths don't jump when real data
 * lands) with every cell replaced by a skeleton bar.
 */
export function SkeletonTable<T extends Record<string, unknown>>({ columns, rows = 6 }: { columns: TableColumn<T>[]; rows?: number }) {
  // design: fake rows only exist to drive column layout; the cast is safe
  // because every renderCell below ignores its argument.
  const data = useMemo(() => Array.from({ length: rows }, (_, i) => ({ __row: i }) as unknown as T), [rows]);
  const skeletonColumns = columns.map((c) => ({ ...c, sortable: false, renderCell: () => <Skeleton height={12} width="60%" /> }));
  return <DataTable data={data} columns={skeletonColumns} idKey={() => Math.random()} />;
}

/**
 * The Sandboxes table's columns — shared by the Sandboxes page and the API
 * key detail page's "sandboxes created by this key" table, so the Key
 * column (and everything else) doesn't drift between the two.
 */
export function sandboxColumns(): TableColumn<SandboxInfo>[] {
  return [
    {
      key: "name",
      header: "Name",
      width: proportional(1.6, { minWidth: 150 }),
      sortable: true,
      renderCell: (sb: SandboxInfo) => (
        <div style={{ minWidth: 0 }}>
          <Link to={`/sandboxes/${sb.id}`} className="sbx-link sbx-truncate" style={{ fontSize: 13 }} title={sb.name || sb.id}>
            {sb.name || sb.id}
          </Link>
          {/* The id line only earns its space when the sandbox has a real name. */}
          {!!sb.name && sb.name !== sb.id && (
            <span className="mono sbx-truncate" style={{ fontSize: 11.5, color: "var(--color-text-disabled)" }}>
              {sb.id}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "state",
      header: "State",
      width: pixel(102),
      sortable: true,
      renderCell: (sb: SandboxInfo) => <StateCell state={sb.state} />,
    },
    {
      key: "isolation",
      header: "Runtime",
      width: proportional(1.3, { minWidth: 168 }),
      renderCell: (sb: SandboxInfo) =>
        sb.isolation ? (
          <span className="sbx-truncate" style={{ fontSize: 12.5 }} title={`${runtimeLabel(sb.isolation)} · ${sb.isolation}`}>
            {runtimeLabel(sb.isolation)} <Muted>· {sb.isolation}</Muted>
          </span>
        ) : (
          <Muted>—</Muted>
        ),
    },
    {
      key: "size",
      header: "Size",
      width: pixel(84),
      renderCell: (sb: SandboxInfo) => (sb.size ? <span style={{ fontSize: 12.5 }}>{sb.size}</span> : <Muted>—</Muted>),
    },
    {
      key: "mem",
      header: "Mem",
      width: pixel(116),
      align: "end" as const,
      renderCell: (sb: SandboxInfo) =>
        sb.usage && sb.limits ? (
          <span className="mono" style={{ fontSize: 12 }} title={`${formatBytes(sb.usage.mem_bytes)} / ${formatBytes(sb.limits.mem_mib * 1024 * 1024)}`}>
            {formatBytes(sb.usage.mem_bytes, true)} / {formatBytes(sb.limits.mem_mib * 1024 * 1024, true)}
          </span>
        ) : (
          <Muted>—</Muted>
        ),
    },
    {
      key: "template",
      header: "Snapshot",
      width: proportional(1, { minWidth: 96 }),
      renderCell: (sb: SandboxInfo) => (
        <span className="mono sbx-truncate" style={{ fontSize: 12 }}>
          {sb.template}
        </span>
      ),
    },
    { key: "host_id", header: "Host", width: pixel(92), sortable: true, renderCell: (sb: SandboxInfo) => <Muted>{sb.host_id}</Muted> },
    {
      key: "pi_session",
      header: "Session",
      width: proportional(1, { minWidth: 110 }),
      renderCell: (sb: SandboxInfo) => <IdCell id={sb.pi_session} to={sb.pi_session ? `/sessions/${sb.pi_session}` : undefined} />,
    },
    {
      key: "api_key",
      header: "Key",
      width: pixel(84),
      renderCell: (sb: SandboxInfo) =>
        sb.api_key_name ? (
          <Link to={`/keys/${sb.api_key_id}`} className="sbx-link sbx-truncate" style={{ fontSize: 12.5 }}>
            {sb.api_key_name}
          </Link>
        ) : (
          <Muted>admin</Muted>
        ),
    },
    {
      key: "labels",
      header: "Labels",
      width: proportional(1, { minWidth: 96 }),
      renderCell: (sb: SandboxInfo) => <LabelChips labels={sb.labels} />,
    },
    {
      key: "created_at",
      header: "Created",
      width: pixel(88),
      sortable: true,
      renderCell: (sb: SandboxInfo) => <Ago value={sb.created_at} />,
    },
    {
      key: "timer",
      header: "Timer",
      width: pixel(110),
      renderCell: (sb: SandboxInfo) => {
        const label = timerLabel(sb);
        return label ? <Muted>{label}</Muted> : null;
      },
    },
    {
      key: "last_activity",
      header: "Last activity",
      width: pixel(126),
      sortable: true,
      renderCell: (sb: SandboxInfo) => <Ago value={sb.last_activity ?? sb.created_at} />,
    },
    {
      key: "actions",
      header: "",
      width: pixel(72),
      align: "end" as const,
      resizable: false,
      renderCell: (sb: SandboxInfo) => <SandboxRowMenu sandbox={sb} />,
    },
  ];
}

/** Dims a cell's content — used for revoked API keys, shown muted at the
 * bottom of the keys table instead of being hidden outright. */
export function MutedCell({ muted, children }: { muted: boolean; children: ReactNode }) {
  return muted ? <span style={{ opacity: 0.55 }}>{children}</span> : <>{children}</>;
}
