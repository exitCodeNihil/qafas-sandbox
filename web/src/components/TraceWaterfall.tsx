import { useEffect, useMemo, useRef, useState } from "react";
import type { OtlpSpan, OtlpTrace } from "../lib/types";
import { attrString } from "../lib/types";
import { basename } from "../lib/format";

type Row = { span: OtlpSpan; depth: number; hasAlert: boolean };

const LABEL_W = 280;
const ROW_H = 26;
const AXIS_H = 24;

function nanosToMsOffset(nano: string, t0: bigint): number {
  return Number((BigInt(nano) - t0) / 1_000_000n);
}

/**
 * Trace waterfall: one horizontal bar per span (tool-call spans at depth 0,
 * process spans nested under them via parentSpanId), a time axis, and red
 * diamond markers for security.alert span events. Plain inline SVG per
 * ponytail rules — no charting library.
 */
export function TraceWaterfall({
  trace,
  selectedSpanId,
  onSelect,
}: {
  trace: OtlpTrace;
  selectedSpanId?: string | null;
  onSelect: (span: OtlpSpan) => void;
}) {
  // OTLP producers omit empty arrays; normalise once so the rest can assume them.
  const spans = (trace.resourceSpans ?? []).flatMap((rs) =>
    (rs.scopeSpans ?? []).flatMap((ss) =>
      (ss.spans ?? []).map((sp) => ({
        ...sp,
        events: (sp.events ?? []).map((e) => ({ ...e, attributes: e.attributes ?? [] })),
        attributes: sp.attributes ?? [],
        parentSpanId: sp.parentSpanId ?? "",
      })),
    ),
  );

  const { rows, t0, totalMs } = useMemo(() => {
    if (spans.length === 0) return { rows: [] as Row[], t0: 0n, totalMs: 1 };
    const byParent = new Map<string, OtlpSpan[]>();
    const roots: OtlpSpan[] = [];
    for (const s of spans) {
      if (s.parentSpanId) {
        if (!byParent.has(s.parentSpanId)) byParent.set(s.parentSpanId, []);
        byParent.get(s.parentSpanId)!.push(s);
      } else {
        roots.push(s);
      }
    }
    const byStart = (a: OtlpSpan, b: OtlpSpan) => (a.startTimeUnixNano < b.startTimeUnixNano ? -1 : 1);
    roots.sort(byStart);
    const out: Row[] = [];
    const walk = (span: OtlpSpan, depth: number) => {
      const hasAlert = span.events.some((e) => e.name === "security.alert");
      out.push({ span, depth, hasAlert });
      const children = [...(byParent.get(span.spanId) ?? [])].sort(byStart);
      for (const c of children) walk(c, depth + 1);
    };
    for (const r of roots) walk(r, 0);

    const t0 = spans.reduce((min, s) => (BigInt(s.startTimeUnixNano) < min ? BigInt(s.startTimeUnixNano) : min), BigInt(spans[0].startTimeUnixNano));
    const tMax = spans.reduce((max, s) => (BigInt(s.endTimeUnixNano ?? s.startTimeUnixNano) > max ? BigInt(s.endTimeUnixNano ?? s.startTimeUnixNano) : max), t0);
    const totalMs = Math.max(Number((tMax - t0) / 1_000_000n), 1);
    return { rows: out, t0, totalMs };
  }, [spans]);

  // Render at the container's real width: a fixed viewBox would scale the text down.
  const box = useRef<HTMLDivElement>(null);
  const [TOTAL_W, setTotalW] = useState(1000);
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setTotalW(Math.max(600, Math.floor(e.contentRect.width))));
    ro.observe(el);
    setTotalW(Math.max(600, Math.floor(el.clientWidth)));
    return () => ro.disconnect();
  }, []);

  if (rows.length === 0) {
    return <p className="sbx-section-desc" style={{ margin: 0 }}>No trace for this session yet.</p>;
  }

  const timelineW = TOTAL_W - LABEL_W;
  const xOf = (ms: number) => LABEL_W + (ms / totalMs) * timelineW;
  const height = AXIS_H + rows.length * ROW_H;

  // 4-5 round-number ticks across the timeline.
  const tickCount = 5;
  const ticks = Array.from({ length: tickCount }, (_, i) => Math.round((totalMs / (tickCount - 1)) * i));

  return (
    <div ref={box} style={{ width: "100%", overflowX: "auto" }}>
    <svg
      width={TOTAL_W}
      height={height}
      style={{ display: "block" }}
      role="img"
      aria-label="Trace waterfall"
    >
      {/* time axis */}
      {ticks.map((ms, i) => (
        <g key={ms}>
          <line x1={xOf(ms)} y1={AXIS_H} x2={xOf(ms)} y2={height} stroke="var(--color-border)" strokeWidth={1} />
          {/* The last tick sits on the right edge - anchor it inside so its
              label is not half-clipped by the SVG viewport. */}
          <text
            x={xOf(ms)}
            y={14}
            fontSize={9}
            fill="var(--color-text-secondary)"
            textAnchor={i === ticks.length - 1 ? "end" : i === 0 ? "start" : "middle"}
          >
            +{ms.toLocaleString()}ms
          </text>
        </g>
      ))}

      {rows.map((row, i) => {
        const y = AXIS_H + i * ROW_H;
        const startMs = nanosToMsOffset(row.span.startTimeUnixNano, t0);
        const endMs = nanosToMsOffset(row.span.endTimeUnixNano ?? row.span.startTimeUnixNano, t0);
        const barX = xOf(startMs);
        const barW = Math.max(xOf(endMs) - barX, 2);
        const isProcess = row.span.name.startsWith("proc:");
        const isSelected = row.span.spanId === selectedSpanId;
        const fill = row.hasAlert ? "var(--color-error)" : isProcess ? "var(--color-text-secondary)" : "var(--color-text-accent)";
        const toolCall = attrString(row.span.attributes, "sbx.tool_call_id");
        const pid = attrString(row.span.attributes, "process.pid");

        // Truncate the label to what fits before the bar column so a long
        // exe path (or deeply nested process) never runs into the timeline.
        const indent = 8 + row.depth * 14;
        const fullLabel = `${row.span.name}${pid ? ` (pid ${pid})` : ""}`;
        const maxChars = Math.max(4, Math.floor((LABEL_W - indent - 8) / 6.2));
        const label = fullLabel.length > maxChars ? `${basename(fullLabel).slice(0, maxChars - 1)}…` : fullLabel;

        return (
          <g key={`${row.span.spanId}-${i}`} className="trace-row" onClick={() => onSelect(row.span)} style={{ cursor: "pointer" }}>
            {/* zebra striping, behind the hover/selection highlight */}
            {i % 2 === 1 && <rect x={0} y={y} width={TOTAL_W} height={ROW_H} fill="var(--color-background-muted)" opacity={0.4} />}
            <rect className="trace-row-hover" x={0} y={y} width={TOTAL_W} height={ROW_H} fill={isSelected ? "var(--color-background-muted)" : "transparent"} />
            <text x={indent} y={y + ROW_H / 2 + 4} fontSize={11} fill="var(--color-text-primary)">
              {label}
              <title>{fullLabel}</title>
            </text>
            <rect x={barX} y={y + 5} width={barW} height={ROW_H - 10} rx={2} fill={fill} opacity={isProcess ? 0.55 : 0.85}>
              <title>
                {row.span.name} · {(endMs - startMs).toLocaleString()}ms{toolCall ? ` · ${toolCall}` : ""}
              </title>
            </rect>
            {row.span.events.map((e, ei) => {
              const ex = xOf(nanosToMsOffset(e.timeUnixNano, t0));
              const isAlert = e.name === "security.alert";
              return (
                <path
                  key={ei}
                  d={`M ${ex} ${y + ROW_H / 2 - 5} l 5 5 l -5 5 l -5 -5 z`}
                  fill={isAlert ? "var(--color-error)" : "var(--color-text-accent)"}
                  stroke="var(--color-background-surface)"
                  strokeWidth={1}
                >
                  <title>
                    {e.name}
                    {isAlert ? ` — ${attrString(e.attributes, "sbx.alert.rule")} (${attrString(e.attributes, "sbx.alert.severity")})` : ""}
                  </title>
                </path>
              );
            })}
          </g>
        );
      })}
    </svg>
    </div>
  );
}
