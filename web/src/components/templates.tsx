import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { NumberInput } from "@astryxdesign/core/NumberInput";
import { Tooltip } from "@astryxdesign/core/Tooltip";
import { useToast } from "@astryxdesign/core/Toast";
import { Muted } from "./tables";
import { StatusDot, Tag, type Tone } from "../ui";
import { api } from "../lib/api";
import type { SnapshotInfo } from "../lib/types";

// Shared by the Templates list and the template detail page.

export const stateTone: Record<SnapshotInfo["state"], Tone> = {
  active: "ready",
  building: "busy",
  error: "danger",
};

export function sourceLabel(sn: { source: SnapshotInfo["source"] }): string {
  const s = sn.source as { image?: string; dockerfile?: string; sandbox_id?: string } | undefined;
  if (s?.image) return s.image;
  if (s?.dockerfile !== undefined) return "Dockerfile";
  if (s?.sandbox_id) return `from ${s.sandbox_id}`;
  return "—";
}

/** Wire `kind` is `"image"` or `"vm"` (crates/qafas/src/snapshots.rs) — "vm" means
 * it was built from a running sandbox, i.e. a checkpoint. Shown as such; never as "vm",
 * which would read as the Docker runtime. */
export function kindLabel(kind: string): string {
  return kind === "vm" ? "checkpoint" : kind;
}

/** Inline "keep warm" editor for one snapshot row: PUTs `/api/snapshots/{name}` on blur
 * or Enter, only when the value actually changed; reverts and toasts on error. */
export function WarmCell({ sn }: { sn: { name: string; warm: number; warmReady: number; memorySnapshot: boolean } }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [value, setValue] = useState<number | null>(sn.warm);
  useEffect(() => setValue(sn.warm), [sn.warm]);

  const commit = async () => {
    const n = value ?? 0;
    if (n === sn.warm) return;
    try {
      await api.put(`/api/snapshots/${sn.name}`, { warm: n });
      void qc.invalidateQueries({ queryKey: ["snapshots"] });
    } catch (err) {
      setValue(sn.warm);
      toast({ body: err instanceof Error ? `Keep warm: ${err.message}` : "Keep warm: update failed", type: "error" });
    }
  };

  return (
    <span className="sbx-row-wrap" style={{ gap: 6 }}>
      <span className="mono" style={{ fontSize: 12.5 }}>{sn.warmReady} ready · keep</span>
      <NumberInput
        label={`Keep warm for ${sn.name}`}
        isLabelHidden
        value={value}
        onChange={setValue}
        onBlur={commit}
        onEnter={commit}
        min={0}
        step={1}
        isIntegerOnly
        size="sm"
        width={56}
      />
      {sn.memorySnapshot && (
        <Tag title="Boots by restoring a memory snapshot instead of a kernel boot">
          <Muted>restore</Muted>
        </Tag>
      )}
    </span>
  );
}

export const gradeTone: Record<string, Tone> = { A: "ready", B: "accent", C: "warning", F: "danger" };

/** v5.2: the worst grade any host gave this template (a template is only as safe as its
 * weakest copy), with the failed checks in the tooltip. */
export function SecurityCell({ rows }: { rows: SnapshotInfo[] }) {
  const scanned = rows.filter((r) => r.security);
  if (scanned.length === 0) return <Muted>not scanned</Muted>;
  const worst = scanned.reduce((w, r) => (r.security!.grade > w.security!.grade ? r : w));
  const sec = worst.security!;
  const failed = sec.findings.filter((c) => !c.ok);
  const tip = failed.length === 0
    ? `All ${sec.findings.length} checks passed`
    : failed.map((c) => `${c.class === "boundary" ? "✕" : "!"} ${c.id}: ${c.detail}`).join("\n");
  return (
    <Tooltip content={<span style={{ whiteSpace: "pre-line" }}>{tip}</span>}>
      <span className="sbx-row" style={{ gap: 6 }}>
        <StatusDot tone={gradeTone[sec.grade] ?? "muted"} label={sec.grade} />
        {failed.length > 0 && <Muted>{failed.length} finding{failed.length === 1 ? "" : "s"}</Muted>}
      </span>
    </Tooltip>
  );
}

