import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  CheckCircle2,
  Radio,
  Database,
  ShieldCheck,
  ShieldAlert,
  MailWarning,
} from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  useEventsList,
  useEventsStatsSummary,
  useEventsTimeseries,
  useIntegrityStatus,
  useLiveStats,
  useSourcesList,
} from "../api/hooks";
import type { EventRow, TimeseriesPoint } from "../api/types";
import KpiCard from "../components/KpiCard";
import ChartPanel from "../components/ChartPanel";
import Badge from "../components/Badge";
import Skeleton from "../components/Skeleton";
import { colorForKey } from "../lib/colors";
import { formatClockTime, formatCount, formatEps, formatPercent } from "../lib/format";
import { actionLabel, actionTone, classLabel, severityLabel, severityTone } from "../lib/ocsf";
import { THEME } from "../lib/theme";

const TIMESERIES_INTERVAL = "1m";
const TIMESERIES_WINDOW = "1h";
const CLASS_ORDER = [4001, 4002, 4003, 2004];

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

/** One row per minute bucket, one column per source_type, values in events/sec. */
function pivotTimeseries(points: TimeseriesPoint[]): {
  rows: Record<string, number | string>[];
  sources: string[];
} {
  const sources = Array.from(new Set(points.map((p) => p.source_type))).sort();
  const byBucket = new Map<string, Record<string, number>>();
  for (const point of points) {
    const row = byBucket.get(point.bucket) ?? {};
    row[point.source_type] = point.events;
    byBucket.set(point.bucket, row);
  }
  const buckets = Array.from(byBucket.keys()).sort();
  const rows = buckets.map((bucket) => {
    // "YYYY-MM-DDTHH:MM:SS" or "YYYY-MM-DD HH:MM:SS" - both put HH:MM at [11,16)
    const row: Record<string, number | string> = { bucket, label: bucket.slice(11, 16) };
    for (const source of sources) {
      row[source] = (byBucket.get(bucket)?.[source] ?? 0) / 60; // events/min -> events/sec
    }
    return row;
  });
  return { rows, sources };
}

function eventDestination(row: EventRow): string {
  const src = row.src_ip ? `${row.src_ip}${row.src_port ? `:${row.src_port}` : ""}` : "—";
  const dst = row.dst_ip ? `${row.dst_ip}${row.dst_port ? `:${row.dst_port}` : ""}` : "—";
  return `${src} → ${dst}`;
}

export default function Overview() {
  const navigate = useNavigate();

  const { eps, isFetching: liveFetching } = useLiveStats();
  const summaryQuery = useEventsStatsSummary(true);
  const timeseriesQuery = useEventsTimeseries(TIMESERIES_INTERVAL, TIMESERIES_WINDOW, true);
  const sourcesQuery = useSourcesList(true);
  const integrityQuery = useIntegrityStatus(true);
  const recentQuery = useEventsList({ page: 1, page_size: 10 }, true);

  const summary = summaryQuery.data;
  const integrity = integrityQuery.data;

  const { rows: timeseriesRows, sources: timeseriesSources } = useMemo(
    () => pivotTimeseries(timeseriesQuery.data?.points ?? []),
    [timeseriesQuery.data],
  );

  const sourceDonutData = useMemo(
    () =>
      [...(summary?.by_source_type ?? [])]
        .sort((a, b) => b.events - a.events)
        .map((s) => ({ name: s.source_type, value: s.events })),
    [summary],
  );

  const classBarData = useMemo(() => {
    const byUid = new Map((summary?.by_class_uid ?? []).map((c) => [c.class_uid, c.events]));
    const known = CLASS_ORDER.filter((uid) => byUid.has(uid)).map((uid) => ({
      class_uid: uid,
      name: classLabel(uid),
      value: byUid.get(uid) ?? 0,
    }));
    const extra = (summary?.by_class_uid ?? [])
      .filter((c) => !CLASS_ORDER.includes(c.class_uid))
      .map((c) => ({ class_uid: c.class_uid, name: classLabel(c.class_uid), value: c.events }));
    return [...known, ...extra];
  }, [summary]);

  const sourcesActive = sourcesQuery.data?.filter((s) => s.enabled).length;
  const sourcesTotal = sourcesQuery.data?.length;

  const integrityTone = !integrity
    ? "default"
    : integrity.ledger_entries === 0
      ? "default"
      : integrity.chain_verified
        ? "ok"
        : "bad";
  const integrityLabel = !integrity
    ? "—"
    : integrity.ledger_entries === 0
      ? "NO LEDGER"
      : integrity.chain_verified
        ? "VERIFIED"
        : "BROKEN";

  const dlqRate = summary?.dlq_rate ?? null;
  const dlqTone = dlqRate === null ? "default" : dlqRate === 0 ? "ok" : dlqRate > 0.05 ? "bad" : "warn";

  return (
    <div className="space-y-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-6">
        <KpiCard
          label="Events / sec"
          icon={Activity}
          loading={summaryQuery.isLoading}
          value={formatEps(eps)}
          sub={liveFetching ? "updating…" : "live"}
        />
        <KpiCard
          label="Parse success"
          icon={CheckCircle2}
          loading={summaryQuery.isLoading}
          value={formatPercent(summary?.parse_success_rate ?? null)}
          tone={
            summary?.parse_success_rate == null
              ? "default"
              : summary.parse_success_rate >= 0.95
                ? "ok"
                : summary.parse_success_rate >= 0.8
                  ? "warn"
                  : "bad"
          }
        />
        <KpiCard
          label="Sources active"
          icon={Radio}
          loading={sourcesQuery.isLoading}
          value={sourcesActive !== undefined ? `${sourcesActive}` : "—"}
          sub={sourcesTotal !== undefined ? `of ${sourcesTotal} loaded` : undefined}
        />
        <KpiCard
          label="Events normalized"
          icon={Database}
          loading={summaryQuery.isLoading}
          value={formatCount(summary?.total_events)}
          sub="total, all sources"
        />
        <KpiCard
          label="Integrity"
          icon={integrityTone === "bad" ? ShieldAlert : ShieldCheck}
          loading={integrityQuery.isLoading}
          large={false}
          value={
            <Badge tone={integrityTone === "default" ? "muted" : integrityTone}>{integrityLabel}</Badge>
          }
          sub={integrity ? `${formatCount(integrity.ledger_entries)} ledger entries` : undefined}
        />
        <KpiCard
          label="Dead letter rate"
          icon={MailWarning}
          loading={summaryQuery.isLoading}
          value={formatPercent(dlqRate)}
          tone={dlqTone}
          sub={summary ? `${formatCount(summary.dlq_total)} total` : undefined}
        />
      </div>

      {/* EPS over time, stacked by source */}
      <ChartPanel
        title="Events / sec — last hour"
        subtitle="1-minute buckets, stacked by source_type · updates every 2s"
        loading={timeseriesQuery.isLoading}
        height={320}
      >
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={timeseriesRows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
            <CartesianGrid stroke={THEME.border} vertical={false} />
            <XAxis dataKey="label" tick={AXIS_TICK} axisLine={{ stroke: THEME.border }} tickLine={false} />
            <YAxis tick={AXIS_TICK} axisLine={{ stroke: THEME.border }} tickLine={false} width={40} />
            <Tooltip {...TOOLTIP_STYLE} />
            <Legend wrapperStyle={{ fontSize: 12, color: THEME.textMuted }} />
            {timeseriesSources.map((source) => (
              <Area
                key={source}
                type="monotone"
                dataKey={source}
                name={source}
                stackId="eps"
                stroke={colorForKey(source)}
                fill={colorForKey(source)}
                fillOpacity={0.55}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </ChartPanel>

      {/* distribution charts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <ChartPanel
          title="Events by source"
          subtitle="share of normalized events"
          loading={summaryQuery.isLoading}
          height={300}
        >
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Tooltip {...TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 12, color: THEME.textMuted }} />
              <Pie
                data={sourceDonutData}
                dataKey="value"
                nameKey="name"
                innerRadius="55%"
                outerRadius="85%"
                paddingAngle={2}
                stroke={THEME.bgPanel}
                strokeWidth={2}
              >
                {sourceDonutData.map((entry) => (
                  <Cell key={entry.name} fill={colorForKey(entry.name)} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </ChartPanel>

        <ChartPanel
          title="Events by OCSF class"
          subtitle="network / http / dns / detection finding"
          loading={summaryQuery.isLoading}
          height={300}
        >
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={classBarData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={THEME.border} vertical={false} />
              <XAxis dataKey="name" tick={AXIS_TICK} axisLine={{ stroke: THEME.border }} tickLine={false} />
              <YAxis tick={AXIS_TICK} axisLine={{ stroke: THEME.border }} tickLine={false} width={40} />
              <Tooltip {...TOOLTIP_STYLE} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {classBarData.map((entry) => (
                  <Cell key={entry.class_uid} fill={colorForKey(String(entry.class_uid))} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartPanel>
      </div>

      {/* recent events */}
      <div className="rounded-lg border border-border bg-bg-panel">
        <div className="border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold text-text">Most recent events</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wide text-text-faint">
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Src → Dst</th>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Severity</th>
              </tr>
            </thead>
            <tbody>
              {recentQuery.isLoading
                ? Array.from({ length: 10 }).map((_, i) => (
                    <tr key={i} className="border-b border-border-subtle">
                      <td className="px-4 py-2.5" colSpan={5}>
                        <Skeleton className="h-4 w-full" />
                      </td>
                    </tr>
                  ))
                : (recentQuery.data?.items ?? []).map((row) => (
                    <tr
                      key={row.event_uid}
                      onClick={() => navigate(`/events/${encodeURIComponent(row.event_uid)}`)}
                      className="cursor-pointer border-b border-border-subtle transition-colors last:border-b-0 hover:bg-bg-elevated"
                    >
                      <td className="px-4 py-2.5 font-mono text-text-muted">
                        {formatClockTime(row.time ?? null)}
                      </td>
                      <td className="px-4 py-2.5 text-text">{row.source_type ?? "—"}</td>
                      <td className="px-4 py-2.5 font-mono text-text-muted">{eventDestination(row)}</td>
                      <td className="px-4 py-2.5">
                        <Badge tone={actionTone(row.action_id ?? null)}>
                          {row.action ?? actionLabel(row.action_id ?? null)}
                        </Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <Badge tone={severityTone(row.severity_id ?? null)}>
                          {row.severity ?? severityLabel(row.severity_id ?? null)}
                        </Badge>
                      </td>
                    </tr>
                  ))}
              {!recentQuery.isLoading && (recentQuery.data?.items.length ?? 0) === 0 && (
                <tr>
                  <td className="px-4 py-6 text-center text-text-faint" colSpan={5}>
                    No events yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
