import type { EventType } from "./types";

/** Timeline filter chips. Anything not covered here (sandbox.*, pool.refill,
 * sandbox.tier_selected, error) is structural and always shown. */
export const EVENT_CHIPS = [
  { key: "exec", label: "Exec", types: ["exec.start", "exec.end"] },
  { key: "file", label: "File", types: ["file.read", "file.write", "file.edit", "file.access"] },
  { key: "net", label: "Net", types: ["net.connect"] },
  { key: "egress", label: "Egress", types: ["egress.allow", "egress.deny"] },
  { key: "process", label: "Process", types: ["process.start", "process.exit"] },
  { key: "alert", label: "Alert", types: ["security.alert"] },
  { key: "browser", label: "Browser", types: ["browser.navigate"] },
] as const satisfies { key: string; label: string; types: EventType[] }[];

const typeToChip = new Map<EventType, string>();
for (const chip of EVENT_CHIPS) for (const t of chip.types) typeToChip.set(t as EventType, chip.key);

export function chipOf(type: EventType): string | null {
  return typeToChip.get(type) ?? null;
}
