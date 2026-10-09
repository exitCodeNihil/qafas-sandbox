import type { ApiKeyLimits } from "./types";
import { ttlLabel } from "./format";

/** Display form of a key's prefix — `ApiKey.prefix` is just the random 8
 * chars (confirmed against the live control plane), the "sbx_" literal and
 * the "_…" (secret withheld) are added for display. */
export function keyPrefixLabel(prefix: string): string {
  return `sbx_${prefix}_…`;
}

/** Short runtime label for a limits summary — RUNTIMES' own labels ("Firecracker
 * microVM", "Docker container") are too long for a table cell. */
const TIER_SHORT: Record<string, string> = { remote: "Firecracker", vm: "Docker", native: "Process" };

/**
 * Compact one-line limits summary for a table cell, e.g.
 * "max 5 live · 60/h · Docker,Firecracker · ttl 2h". Every field is optional
 * (absent = unlimited per protocol.md §4b); no set field at all reads
 * "unlimited". "max" on the concurrency figure distinguishes it from a live
 * count elsewhere on the same row (defect: read as "1 live" next to a LIVE
 * column showing 0).
 */
export function limitsSummary(limits: ApiKeyLimits | undefined | null): string {
  const parts: string[] = [];
  if (limits?.max_concurrent) parts.push(`max ${limits.max_concurrent} live`);
  if (limits?.max_per_hour) parts.push(`${limits.max_per_hour}/h`);
  if (limits?.allowed_tiers?.length) parts.push(limits.allowed_tiers.map((t) => TIER_SHORT[t] ?? t).join(","));
  if (limits?.max_ttl_secs) parts.push(`ttl ${ttlLabel(limits.max_ttl_secs)}`);
  if (limits?.allowed_sizes?.length) parts.push(`sizes ${limits.allowed_sizes.join(",")}`);
  if (limits?.max_cpus) parts.push(`≤ ${limits.max_cpus} cpu`);
  if (limits?.max_mem_mib) parts.push(`≤ ${limits.max_mem_mib} MiB`);
  if (limits?.max_disk_mib) parts.push(`≤ ${limits.max_disk_mib} MiB disk`);
  return parts.length ? parts.join(" · ") : "unlimited";
}

/** `since` selector for key usage — ISO timestamps, matching how the store
 * already compares `since` for alerts (`ts >= ?`, store/v2.go ListAlerts). */
export const SINCE_OPTIONS = [
  { value: "24h", label: "24h", ms: 24 * 3600_000 },
  { value: "7d", label: "7d", ms: 7 * 24 * 3600_000 },
  { value: "30d", label: "30d", ms: 30 * 24 * 3600_000 },
] as const;
export type SinceKey = (typeof SINCE_OPTIONS)[number]["value"];

export function sinceIso(key: SinceKey): string {
  const opt = SINCE_OPTIONS.find((o) => o.value === key) ?? SINCE_OPTIONS[0];
  return new Date(Date.now() - opt.ms).toISOString();
}
