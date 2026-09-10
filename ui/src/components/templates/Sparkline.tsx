import { THEME } from "../../lib/theme";

interface SparklineProps {
  values: number[];
  width?: number;
  height?: number;
}

/** A minimal inline SVG sparkline — no charting library needed for one line in a table cell. */
export default function Sparkline({ values, width = 88, height = 24 }: SparklineProps) {
  if (values.length < 2) {
    return <span className="text-xs text-text-faint">—</span>;
  }

  const max = Math.max(...values, 0.0001);
  const min = 0; // rates are non-negative; anchoring at 0 makes bar height meaningful
  const stepX = width / (values.length - 1);
  const points = values.map((v, i) => {
    const x = i * stepX;
    const y = height - ((v - min) / (max - min)) * height;
    return [x, Number.isFinite(y) ? y : height];
  });

  const linePath = points.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const areaPath = `${linePath} L${width},${height} L0,${height} Z`;
  const last = points[points.length - 1];

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="overflow-visible">
      <path d={areaPath} fill={THEME.accent} fillOpacity={0.15} stroke="none" />
      <path d={linePath} fill="none" stroke={THEME.accent} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r={2} fill={THEME.accent} />
    </svg>
  );
}
