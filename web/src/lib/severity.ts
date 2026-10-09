import type { Severity } from "./types";

/** Dot color per severity — for the compact SeverityCluster indicator. */
export function severityColor(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "var(--color-error)";
    case "high":
      return "var(--color-icon-orange)";
    case "medium":
      return "var(--color-warning)";
    case "low":
      return "var(--color-text-secondary)";
  }
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
export const SEVERITY_ABBR: Record<Severity, string> = {
  critical: "crit",
  high: "high",
  medium: "med",
  low: "low",
};

/** Total alert count across all severities — the shared sort/summary key. */
export function alertsTotal(alerts: Record<Severity, number>): number {
  return alerts.critical + alerts.high + alerts.medium + alerts.low;
}
