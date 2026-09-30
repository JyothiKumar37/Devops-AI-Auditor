// Lightweight, dependency-free multi-series line chart rendered as SVG.
// The project ships no charting library, so trends are drawn by hand with a
// fixed viewBox that scales responsively to the container width.

export interface TrendSeries {
  label: string;
  color: string;
  values: number[];
}

interface TrendChartProps {
  series: TrendSeries[];
  labels: string[];
  height?: number;
  /** Fixed maximum for the Y axis (e.g. 100 for scores). Auto when omitted. */
  yMax?: number;
  /** Optional caption formatter for the latest value in the legend. */
  unit?: string;
}

const WIDTH = 640;
const PAD_X = 36;
const PAD_TOP = 12;
const PAD_BOTTOM = 26;

export function TrendChart({ series, labels, height = 200, yMax, unit }: TrendChartProps) {
  const n = labels.length;
  const innerW = WIDTH - PAD_X * 2;
  const innerH = height - PAD_TOP - PAD_BOTTOM;

  const dataMax = Math.max(
    1,
    yMax ?? Math.max(...series.flatMap((s) => s.values), 0),
  );

  const x = (i: number) => (n <= 1 ? PAD_X + innerW / 2 : PAD_X + (innerW * i) / (n - 1));
  const y = (v: number) => PAD_TOP + innerH * (1 - Math.min(v, dataMax) / dataMax);

  // Horizontal gridlines at 0/25/50/75/100% of the max.
  const gridlines = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
    yPos: PAD_TOP + innerH * (1 - f),
    value: Math.round(dataMax * f),
  }));

  return (
    <div>
      <svg
        viewBox={`0 0 ${WIDTH} ${height}`}
        className="w-full"
        role="img"
        preserveAspectRatio="none"
      >
        {gridlines.map((g) => (
          <g key={g.value}>
            <line
              x1={PAD_X}
              y1={g.yPos}
              x2={WIDTH - PAD_X}
              y2={g.yPos}
              stroke="rgba(148,163,184,0.22)"
              strokeWidth={1}
            />
            <text x={4} y={g.yPos + 3} className="fill-slate-400" fontSize={9}>
              {g.value}
            </text>
          </g>
        ))}

        {series.map((s) => {
          const pts = s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ");
          return (
            <g key={s.label}>
              <polyline
                points={pts}
                fill="none"
                stroke={s.color}
                strokeWidth={2}
                strokeLinejoin="round"
                strokeLinecap="round"
              />
              {s.values.map((v, i) => (
                <circle key={i} cx={x(i)} cy={y(v)} r={2.5} fill={s.color} />
              ))}
            </g>
          );
        })}

        {labels.map((label, i) =>
          // Show at most ~8 x-axis labels to avoid crowding.
          n <= 8 || i % Math.ceil(n / 8) === 0 || i === n - 1 ? (
            <text
              key={i}
              x={x(i)}
              y={height - 8}
              textAnchor="middle"
              className="fill-slate-400"
              fontSize={9}
            >
              {label}
            </text>
          ) : null,
        )}
      </svg>

      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {series.map((s) => {
          const last = s.values[s.values.length - 1];
          return (
            <span key={s.label} className="inline-flex items-center gap-1.5 text-xs text-slate-600">
              <span className="h-2 w-2 rounded-full" style={{ background: s.color }} aria-hidden />
              {s.label}
              {typeof last === "number" ? (
                <span className="font-semibold tabular-nums text-slate-800">
                  {last}
                  {unit ?? ""}
                </span>
              ) : null}
            </span>
          );
        })}
      </div>
    </div>
  );
}
