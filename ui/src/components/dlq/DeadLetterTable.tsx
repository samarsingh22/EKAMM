import type { DeadLetterOut } from "../../api/types";
import Badge from "../Badge";
import Skeleton from "../Skeleton";
import { formatClockTime } from "../../lib/format";

interface DeadLetterTableProps {
  items: DeadLetterOut[] | undefined;
  loading: boolean;
}

function sourceHint(detail: Record<string, unknown>): string {
  const source = detail?.source_type;
  return typeof source === "string" && source ? source : "—";
}

export default function DeadLetterTable({ items, loading }: DeadLetterTableProps) {
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-bg-panel">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-text">Dead letters</h2>
        <p className="text-xs text-text-faint">Events that failed a pipeline stage — raw bytes preserved, replayable.</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-text-faint">
              <th className="px-4 py-2 font-medium">Time</th>
              <th className="px-4 py-2 font-medium">Reason</th>
              <th className="px-4 py-2 font-medium">Stage</th>
              <th className="px-4 py-2 font-medium">Source hint</th>
              <th className="px-4 py-2 font-medium">Raw preview</th>
              <th className="px-4 py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 10 }).map((_, i) => (
                <tr key={i} className="border-b border-border-subtle">
                  <td className="px-4 py-3" colSpan={6}>
                    <Skeleton className="h-4 w-full" />
                  </td>
                </tr>
              ))
            ) : !items || items.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-text-faint" colSpan={6}>
                  No dead letters match this filter.
                </td>
              </tr>
            ) : (
              items.map((d) => (
                <tr key={`${d.event_uid}-${d.ts_ns}`} className="border-b border-border-subtle align-top hover:bg-bg-elevated">
                  <td className="px-4 py-2.5 whitespace-nowrap font-mono text-xs text-text-muted">
                    {formatClockTime(d.ts_ns)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-text">{d.reason}</td>
                  <td className="px-4 py-2.5 text-xs text-text-muted">{d.stage}</td>
                  <td className="px-4 py-2.5 font-mono text-xs text-text-muted">{sourceHint(d.detail)}</td>
                  <td className="max-w-md px-4 py-2.5">
                    <span className="line-clamp-2 break-all font-mono text-xs text-text-muted">
                      {d.raw_preview}
                      {d.raw_truncated && <span className="text-text-faint"> …</span>}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <Badge tone={d.resolved ? "ok" : "warn"}>{d.resolved ? "resolved" : "open"}</Badge>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
