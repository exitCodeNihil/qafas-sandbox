/**
 * Console design system — the primitives every page is assembled from.
 *
 * Astryx owns inputs, menus, dialogs and the table engine. This module owns
 * the layout vocabulary on top: page header, section, card, stat, key/value
 * grid, status dot, tag, toolbar, data table, empty state, drawer chrome and
 * code block. Styling lives in app.css (class names prefixed `sbx-`); this
 * file is only structure, so the visual rules stay in one place.
 */
import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { Table } from "@astryxdesign/core/Table";
import type { TableColumn, TablePlugin } from "@astryxdesign/core/Table";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Link } from "react-router-dom";
import { IconCopy, IconCheck, IconSearch, IconChevronDown } from "./components/icons";

// ── Page ────────────────────────────────────────────────────────

export function PageHeader({
  title,
  description,
  id,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  /** Monospace secondary line under the title — a resource's raw id. */
  id?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="sbx-page-head">
      <div style={{ minWidth: 0 }}>
        <h1 className="sbx-page-title">{title}</h1>
        {description && <p className="sbx-page-subtitle">{description}</p>}
        {id && <p className="sbx-page-id">{id}</p>}
      </div>
      {actions && <div className="sbx-page-actions">{actions}</div>}
    </header>
  );
}

export function Section({
  title,
  description,
  action,
  children,
}: {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section>
      {(title || action) && (
        <div className="sbx-section-head">
          <div style={{ minWidth: 0 }}>
            {title && <h2 className="sbx-section-title">{title}</h2>}
            {description && <p className="sbx-section-desc">{description}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

export function Card({
  children,
  padding = "default",
  className,
  style,
}: {
  children: ReactNode;
  padding?: "default" | "tight" | "flush";
  className?: string;
  style?: CSSProperties;
}) {
  const pad = padding === "tight" ? " sbx-card-tight" : padding === "flush" ? " sbx-card-flush" : "";
  return (
    <div className={`sbx-card${pad}${className ? ` ${className}` : ""}`} style={style}>
      {children}
    </div>
  );
}

// ── Stats ───────────────────────────────────────────────────────

export function StatCard({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="sbx-card sbx-stat">
      <span className="sbx-stat-label">{label}</span>
      <span className="sbx-stat-value">{value}</span>
      <span className="sbx-stat-sub">{sub ?? ""}</span>
    </div>
  );
}

export function StatRow({ columns = 4, children }: { columns?: 3 | 4; children: ReactNode }) {
  return <div className={columns === 3 ? "sbx-stats sbx-stats-3" : "sbx-stats"}>{children}</div>;
}

// ── Key/value grid ──────────────────────────────────────────────

export type KV = { label: string; value: ReactNode; wide?: boolean };

/**
 * Label-above-value metadata grid. Rows whose value is null/undefined are
 * dropped outright rather than rendered as a wall of em dashes — a value is
 * only shown as "—" when the caller passes it deliberately.
 */
export function KeyValueGrid({ items, columns = 4 }: { items: (KV | null | false | undefined)[]; columns?: 2 | 3 | 4 }) {
  const rows = items.filter((i): i is KV => !!i && i.value !== null && i.value !== undefined && i.value !== "");
  if (rows.length === 0) return null;
  return (
    <div className="sbx-kv" style={{ ["--kv-cols" as string]: columns }}>
      {rows.map((r) => (
        <div key={r.label} className={r.wide ? "sbx-kv-item sbx-kv-wide" : "sbx-kv-item"}>
          <span className="sbx-label">{r.label}</span>
          <span className="sbx-value">{r.value}</span>
        </div>
      ))}
    </div>
  );
}

// ── Status ──────────────────────────────────────────────────────

export type Tone = "ready" | "busy" | "warning" | "muted" | "danger" | "accent";

const TONE_COLOR: Record<Tone, string> = {
  ready: "var(--color-success)",
  busy: "var(--color-text-blue)",
  warning: "var(--color-warning)",
  muted: "var(--color-text-disabled)",
  danger: "var(--color-error)",
  accent: "var(--color-accent)",
};

export function StatusDot({ tone, label, muted }: { tone: Tone; label?: ReactNode; muted?: boolean }) {
  return (
    <span className="sbx-status" data-muted={muted ? "true" : undefined}>
      <span className="sbx-status-dot" style={{ ["--dot" as string]: TONE_COLOR[tone] }} />
      {label}
    </span>
  );
}

// ── Tag ─────────────────────────────────────────────────────────

export function Tag({
  children,
  mono,
  to,
  title,
  tone,
}: {
  children: ReactNode;
  mono?: boolean;
  to?: string;
  title?: string;
  /** Colours the border and text for a value worth flagging at a glance —
   * an "admin" API-key scope, a "trusted" (reduced-isolation) sandbox.
   * Omit for the plain neutral tag every other value gets. */
  tone?: "warning";
}) {
  const cls = `sbx-tag${mono ? " sbx-tag-mono" : ""}${tone ? ` sbx-tag-${tone}` : ""}`;
  if (to)
    return (
      <Link className={cls} to={to} title={title}>
        {children}
      </Link>
    );
  return (
    <span className={cls} title={title}>
      {children}
    </span>
  );
}

export function Tags({ children, nowrap }: { children: ReactNode; nowrap?: boolean }) {
  return <div className={nowrap ? "sbx-tags sbx-tags-nowrap" : "sbx-tags"}>{children}</div>;
}

// ── Toolbar ─────────────────────────────────────────────────────

export function Toolbar({ children, end }: { children?: ReactNode; end?: ReactNode }) {
  return (
    <div className="sbx-toolbar">
      {children}
      {end && <div className="sbx-toolbar-end">{end}</div>}
    </div>
  );
}

export function SearchField({
  value,
  onChange,
  placeholder = "Search…",
  width = 280,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  width?: number;
}) {
  return (
    <TextInput
      label="Search"
      isLabelHidden
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      startIcon={<IconSearch width={14} height={14} />}
      hasClear
      width={width}
    />
  );
}

/** Outlined toggle that fills only when active. */
export function FilterChip({
  label,
  isActive,
  onClick,
}: {
  label: ReactNode;
  isActive: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className="sbx-chip" aria-pressed={isActive} onClick={onClick}>
      {label}
    </button>
  );
}

// ── Data table ──────────────────────────────────────────────────

/**
 * The console's one table look: small-caps headers, 48px rows, hairline
 * dividers, a bordered card around the whole thing. Every list page goes
 * through this so density never drifts between pages.
 */
export function DataTable<T extends Record<string, unknown>>({
  data,
  columns,
  idKey,
  plugins,
  empty,
  textOverflow = "truncate",
}: {
  data: T[];
  columns: TableColumn<T>[];
  idKey: string | ((row: T) => string | number);
  plugins?: Record<string, TablePlugin<T>>;
  empty?: ReactNode;
  /** 'wrap' lets a cell grow taller instead of clipping — needed for columns whose
   * content (chip lists, runtime labels) mustn't lose text to an ellipsis. */
  textOverflow?: "wrap" | "truncate";
}) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const didReset = useRef(false);
  // A table can open scrolled right (astryx's internal scroll wrapper, not this div)
  // once real rows replace the loading skeleton — seen on Templates, where widening
  // cells on data load nudge horizontal scroll. Zero it once, the first time this
  // table has rows; never fights a scroll the viewer does afterwards.
  useEffect(() => {
    if (didReset.current || data.length === 0) return;
    didReset.current = true;
    const scroller = wrapRef.current?.querySelector<HTMLElement>(".astryx-table-scroll-wrapper");
    if (scroller) scroller.scrollLeft = 0;
  }, [data]);

  return (
    <div className="sbx-table" ref={wrapRef}>
      <Table
        density="balanced"
        dividers="rows"
        hasHover
        textOverflow={textOverflow}
        data={data}
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        idKey={idKey as any}
        plugins={plugins}
        emptyState={<div className="sbx-table-empty">{empty ?? "Nothing to show."}</div>}
        columns={columns}
      />
    </div>
  );
}

// ── Empty state ─────────────────────────────────────────────────

export function EmptyState({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="sbx-empty">
      <h2>{title}</h2>
      {description && <p>{description}</p>}
      {actions && <div className="sbx-empty-actions">{actions}</div>}
    </div>
  );
}

/** A one-line inline notice — the replacement for a full-width banner box.
 * `tone` colors it for a pass/fail result (e.g. a test-connection check);
 * the default reads neutral, same as before this prop existed. */
export function Notice({ title, tone = "neutral", children }: { title?: string; tone?: "neutral" | "success" | "error"; children: ReactNode }) {
  return (
    <div className={tone === "neutral" ? "sbx-notice" : `sbx-notice sbx-notice-${tone}`}>
      {title && <strong>{title}</strong>}
      <span>{children}</span>
    </div>
  );
}

// ── Code block ──────────────────────────────────────────────────

/** Monospace, uncoloured, copy button top-right, language label at the left. */
export function CodeBlock({ code, language }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(code).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1400);
      },
      () => {},
    );
  };
  return (
    <div className="sbx-code">
      <div className="sbx-code-bar">
        <span>{language ?? ""}</span>
        <button type="button" className="sbx-code-copy" onClick={copy} aria-label="Copy code">
          {copied ? <IconCheck width={14} height={14} /> : <IconCopy width={14} height={14} />}
        </button>
      </div>
      <pre>{code}</pre>
    </div>
  );
}

// ── Disclosure chevron ──────────────────────────────────────────

export function Chevron({ isOpen }: { isOpen: boolean }) {
  return (
    <IconChevronDown
      width={14}
      height={14}
      style={{ transform: isOpen ? "rotate(180deg)" : undefined, transition: "transform 0.12s ease" }}
    />
  );
}
