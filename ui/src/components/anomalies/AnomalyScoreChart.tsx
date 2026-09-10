import { useMemo } from "react";
import {
  Area,
  Brush,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Scatter,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import clsx from "clsx";

import type { AnomalyTimeline } from "../../api/types";
import ChartPanel from "../ChartPanel";
import { THEME } from "../../lib/theme";

interface AnomalyScoreChartProps {
  data: AnomalyTimeline | undefined;
  loading: boolean;
  window: string;
  windows: readonly string[];
  onWindowChange: (window: string) => void;
}

const AXIS_TICK = { fill: THEME.textMuted, fontSize: 12 };
const TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: THEME.bgElevated,
    border: `1px solid ${THEME.border}`,
    borderRadius: 8,
    fontSize: 13,
  },
  labelStyle: { color: THEME.textMuted },
  itemStyle: { color: THEME.textMuted },
};
const RED = "#f87171";

interface Row {
  label: string;
  max: number;
  mean: number;
  /** `max` again, but only on buckets that contain at least one flagged event — the red dots. */
  flagged: number | null;
  scored: number;
  anomalies: number;
}

function toRows(data: AnomalyTimeline | undefined): Row[] {
  return (data?.points ?? []).map((point) => {
    const date = new Date(point.bucket_ns / 1_000_000);
    const max = point.max_score ?? 0;
    return {
      label: date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false }),
      max,
      mean: point.mean_score ?? 0,
      flagged: point.anomalies > 0 ? max : null,
      scored: point.scored,
      anomalies: point.anomalies,
    };
  });
}

export default function AnomalyScoreChart({
  data,
  loading,
  window,
  windows,
  onWindowChange,
}: AnomalyScoreChartProps) {
  const rows = useMemo(() => toRows(data), [data]);
  const flaggedBuckets = rows.filter((r) => r.flagged !== null).length;

  const windowPicker = (
    <div className="flex items-center gap-1">
      {windows.map((w) => (
        <button
          key={w}
          type="button"
          onClick={() => onWindowChange(w)}
          className={clsx(
            "rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
            w === window ? "bg-accent-bg text-accent" : "text-text-muted hover:bg-bg-elevated",
          )}
        >
          {w}
        </button>
      ))}
    </div>
  );

  return (
    <ChartPanel
      title="Anomaly score over time"
      subtitle={
        rows.length === 0
          ? "no scored events in this window yet"
          : `peak score per bucket · ${flaggedBuckets} bucket${flaggedBuckets === 1 ? "" : "s"} with a flagged event · drag the handles below to zoom`
      }
      loading={loading}
      height={320}
      actions={windowPicker}
    >
      {rows.length === 0 ? (
        <div className="flex h-full items-center justify-center text-sm text-text-faint">
          Score a day of events (<code className="mx-1 text-text-muted">ulpf ml score</code>) to
          populate this chart.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="anomalyMax" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={THEME.accent} stopOpacity={0.28} />
                <stop offset="100%" stopColor={THEME.accent} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke={THEME.border} vertical={false} />
            <XAxis
              dataKey="label"
              tick={AXIS_TICK}
              axisLine={{ stroke: THEME.border }}
              tickLine={false}
              minTickGap={24}
            />
            <YAxis
              tick={AXIS_TICK}
              axisLine={{ stroke: THEME.border }}
              tickLine={false}
              width={44}
              domain={[0, "auto"]}
            />
            <Tooltip {...TOOLTIP_STYLE} />
            <Area
              type="monotone"
              dataKey="max"
              name="peak score"
              stroke={THEME.accent}
              strokeWidth={1.5}
              fill="url(#anomalyMax)"
            />
            <Line
              type="monotone"
              dataKey="mean"
              name="mean score"
              stroke={THEME.textMuted}
              strokeWidth={1}
              strokeDasharray="4 3"
              dot={false}
            />
            <Scatter dataKey="flagged" name="flagged" fill={RED} />
            <Brush
              dataKey="label"
              height={22}
              travellerWidth={8}
              stroke={THEME.accent}
              fill={THEME.bgElevated}
            />
          </ComposedChart>
        </ResponsiveContainer>
      )}
    </ChartPanel>
  );
}
