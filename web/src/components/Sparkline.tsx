/**
 * Exec-latency chart. No chart library (WP3 ponytail rule): an inline SVG
 * area that stretches to the card width, with the axis labels rendered as
 * HTML alongside it so they never distort with the plot.
 *
 * The SVG uses a fixed viewBox stretched by `preserveAspectRatio="none"`;
 * every stroke carries `vector-effect="non-scaling-stroke"` so the line
 * keeps a 1.5px weight at any container width.
 */
const VB_W = 1000;
const VB_H = 100;

function tickLabel(v: number, unit: string): string {
  return `${Math.round(v).toLocaleString()}${unit}`;
}

export function LatencyChart({
  values,
  unit = "",
  height = 160,
}: {
  values: number[];
  unit?: string;
  height?: number;
}) {
  if (values.length < 2) {
    return (
      <div
        style={{
          height,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--color-text-secondary)",
          fontSize: 13,
        }}
      >
        Not enough data yet.
      </div>
    );
  }

  const max = Math.max(...values, 1);
  const mid = max / 2;
  const stepX = VB_W / (values.length - 1);
  const points = values.map((v, i) => [i * stepX, VB_H - (v / max) * VB_H] as const);
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `0,${VB_H} ${line} ${VB_W},${VB_H}`;
  const accent = "var(--color-text-accent)";

  const axis = { fontSize: 11, color: "var(--color-text-disabled)", fontVariantNumeric: "tabular-nums" as const };

  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "56px minmax(0, 1fr)", columnGap: 8 }}>
        {/* Y axis — three ticks aligned to the plot's grid lines. */}
        <div
          style={{
            height,
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
            alignItems: "flex-end",
            ...axis,
          }}
        >
          <span style={{ transform: "translateY(-0.5em)" }}>{tickLabel(max, unit)}</span>
          <span>{tickLabel(mid, unit)}</span>
          <span style={{ transform: "translateY(0.5em)" }}>0{unit}</span>
        </div>

        <svg
          className="sbx-chart"
          height={height}
          viewBox={`0 0 ${VB_W} ${VB_H}`}
          preserveAspectRatio="none"
          role="img"
          aria-label={`Exec latency, ${values.length} samples, max ${Math.round(max)}${unit}`}
        >
          {[0, VB_H / 2, VB_H].map((y) => (
            <line
              key={y}
              x1={0}
              y1={y}
              x2={VB_W}
              y2={y}
              stroke="var(--color-border)"
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          <polygon points={area} fill={accent} opacity={0.1} />
          <polyline
            points={line}
            fill="none"
            stroke={accent}
            strokeWidth={1.5}
            strokeLinejoin="round"
            strokeLinecap="round"
            vectorEffect="non-scaling-stroke"
          />
        </svg>
      </div>

      {/* X axis — oldest on the left, newest on the right. */}
      <div style={{ display: "grid", gridTemplateColumns: "56px minmax(0, 1fr)", columnGap: 8, marginTop: 8 }}>
        <span />
        <div style={{ display: "flex", justifyContent: "space-between", ...axis }}>
          <span>oldest</span>
          <span>{values.length} samples</span>
          <span>newest</span>
        </div>
      </div>
    </div>
  );
}
