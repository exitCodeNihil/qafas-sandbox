import type { Event } from "./types";

/** Compact relative time, e.g. "3m ago" — short enough for a table column. Clamped at 0 so a clock-skewed or
 * future-dated fixture timestamp doesn't render as negative. */
export function timeAgo(iso?: string | null): string {
  if (!iso) return "—";
  const secondsAgo = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (secondsAgo < 60) return `${secondsAgo}s ago`;
  if (secondsAgo < 3600) return `${Math.round(secondsAgo / 60)}m ago`;
  if (secondsAgo < 86400) return `${Math.round(secondsAgo / 3600)}h ago`;
  return `${Math.round(secondsAgo / 86400)}d ago`;
}

/** Duration between two ISO timestamps, e.g. "230ms", "4.1s", "2.0m", "3.1h". */
export function durationLabel(startIso: string, endIso: string): string {
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime();
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${(ms / 60_000).toFixed(1)}m`;
  return `${(ms / 3_600_000).toFixed(1)}h`;
}

/** Whole-number duration from a count of seconds, e.g. "45s", "12m", "23h" — the unit a resolved
 * lifecycle timer (`auto_stop_secs - idle_secs`, `auto_delete_secs` minus time since a state
 * change, an API key's `max_ttl_secs`) is shown in. Rounds rather than truncating so
 * "59m30s" reads as "1h", not "59m". */
export function ttlLabel(secs: number): string {
  const s = Math.max(0, Math.round(secs));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  return `${Math.round(s / 3600)}h`;
}

/** MiB as a compact binary size, e.g. "512 MiB", "2 GiB" (`compact`: "512M", "2G") —
 * the unit `SandboxLimits.mem_mib` / `disk_mib` are already expressed in. */
export function formatMiB(mib?: number | null, compact = false): string {
  if (mib === undefined || mib === null) return "—";
  const gib = mib >= 1024;
  const value = gib ? mib / 1024 : mib;
  const rounded = value % 1 === 0 ? String(value) : value.toFixed(1);
  const unit = gib ? "GiB" : "MiB";
  return compact ? `${rounded}${unit[0]}` : `${rounded} ${unit}`;
}

/** Bytes as a compact binary size in the same units as `formatMiB` — for `SandboxUsage` fields. */
export function formatBytes(bytes?: number | null, compact = false): string {
  if (bytes === undefined || bytes === null) return "—";
  return formatMiB(bytes / (1024 * 1024), compact);
}

/** p-th percentile (0..1) of a sample array by nearest-rank: sort ascending, take
 * index ceil(p·n)−1. Callers should hide the result for a sample too small to be
 * meaningful (n < 20 is the console's own threshold for p95). */
export function percentile(values: number[], p: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(p * sorted.length) - 1));
  return sorted[idx];
}

/** Basename of a filesystem/exe path — for compact display with the full path in a title. */
export function basename(p: string): string {
  const parts = p.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? p;
}

/**
 * One-line human summary of an event's payload, so a timeline row can be
 * scanned without expanding its raw JSON. Falls back to the event type.
 */
export function summarizeEvent(e: Event): string {
  const d = e.data as Record<string, unknown>;
  switch (e.type) {
    case "exec.start":
      return String(d.cmd ?? "exec");
    case "exec.end":
      return `exit ${d.exit ?? "?"} · ${d.duration_ms ?? "?"}ms`;
    case "file.read":
    case "file.write":
    case "file.edit":
    case "file.access":
      return String(d.path ?? "");
    case "browser.navigate":
      return String(d.url ?? "");
    case "egress.allow":
    case "egress.deny":
      return `${d.host ?? d.dst ?? "?"}${d.port ? `:${d.port}` : ""}${d.reason ? ` — ${d.reason}` : ""}`;
    case "net.connect":
      return `${d.host ?? d.dst ?? "?"}${d.port ? `:${d.port}` : ""}`;
    case "process.start":
      return Array.isArray(d.argv) ? d.argv.join(" ") : "process start";
    case "process.exit": {
      const exit = d.exit;
      if (exit !== null && exit !== undefined) return `exit ${exit}`;
      if (d.signal) return `signal ${d.signal}`;
      return "ended";
    }
    case "security.alert":
      return String(d.msg ?? d.rule ?? "alert");
    case "sandbox.created":
      return `${d.template ?? ""} · ${d.backend ?? ""}`;
    case "sandbox.ready":
      return d.boot_ms !== undefined ? `booted in ${d.boot_ms}ms` : "";
    case "sandbox.destroyed":
      return String(d.reason ?? "");
    case "sandbox.tier_selected":
      return `${d.selected ?? "?"}${d.reason ? ` — ${d.reason}` : ""}`;
    case "pool.refill":
      return String(d.template ?? "");
    case "error":
      return String(d.message ?? d.error ?? "error");
    default:
      return "";
  }
}
