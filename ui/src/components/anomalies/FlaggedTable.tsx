import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowUpRight } from "lucide-react";

import type { AnomalyRow } from "../../api/types";
import Skeleton from "../Skeleton";
import { formatClockTime, formatRelativeTime } from "../../lib/format";
import { explainInEnglish } from "../../lib/anomalyFeatures";

interface FlaggedTableProps {
  rows: AnomalyRow[] | undefined;
  loading: boolean;
}

export default function FlaggedTable({ rows, loading }: FlaggedTableProps) {
  const navigate = useNavigate();
  const maxScore = useMemo(
    () => Math.max(0.0001, ...(rows ?? []).map((r) => r.anomaly_score)),
    [rows],
  );

  return (
    <div className="rounded-lg border border-border bg-bg-panel">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-text">Flagged events</h2>
        <p className="text-xs text-text-faint">
          Every event the Isolation Forest scored as an outlier, newest first — with the three
          features that put it there.
        </p>
      </div>

      {loading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : !rows || rows.length === 0 ? (
        <p className="p-6 text-center text-sm text-text-faint">
          No flagged events. Train a model and score some traffic to see anomalies here.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wide text-text-faint">
                <th className="px-4 py-2 font-medium">When</th>
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Score</th>
                <th className="px-4 py-2 font-medium">Why it fired — top 3 features</th>
                <th className="px-4 py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const href = `/events/${encodeURIComponent(row.event_uid)}`;
                return (
                  <tr
                    key={`${row.event_uid}:${row.scored_at_ns ?? 0}`}
                    onClick={() => navigate(href)}
                    className="cursor-pointer border-b border-border-subtle align-top transition-colors last:border-b-0 hover:bg-bg-elevated"
                  >
                    <td className="whitespace-nowrap px-4 py-3">
                      <div className="text-text">{formatRelativeTime(row.event_time_ns)}</div>
                      <div className="font-mono text-[11px] text-text-faint">
                        {formatClockTime(row.event_time_ns)}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-text-muted">
                      {row.source_type ?? "—"}
                      {row.src_ip && (
                        <div className="font-mono text-[11px] text-text-faint">{row.src_ip}</div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <div className="font-mono text-sm font-semibold text-status-bad">
                        {row.anomaly_score.toFixed(3)}
                      </div>
                      <div className="mt-1 h-1 w-20 overflow-hidden rounded-full bg-bg-inset">
                        <div
                          className="h-full rounded-full bg-status-bad"
                          style={{
                            width: `${Math.max(6, Math.min(100, (row.anomaly_score / maxScore) * 100))}%`,
                          }}
                        />
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <ul className="space-y-0.5">
                        {row.explanation.slice(0, 3).map((e, i) => (
                          <li key={`${e.feature}:${i}`} className="text-xs text-text-muted">
                            <span className="text-text-faint">{i + 1}.</span> {explainInEnglish(e)}
                            <span
                              className={
                                e.direction === "high" ? "text-status-bad" : "text-status-warn"
                              }
                            >
                              {" "}
                              ({e.direction}, p{Math.round(e.percentile)})
                            </span>
                          </li>
                        ))}
                        {row.explanation.length === 0 && (
                          <li className="text-xs text-text-faint">no explanation recorded</li>
                        )}
                      </ul>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-right">
                      <span className="inline-flex items-center gap-1 text-xs font-medium text-accent">
                        event <ArrowUpRight className="h-3.5 w-3.5" />
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
