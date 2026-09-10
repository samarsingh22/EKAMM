import { TrendingDown, TrendingUp } from "lucide-react";
import clsx from "clsx";

import type { DriftEntry } from "../../api/types";
import Skeleton from "../Skeleton";
import { formatCount } from "../../lib/format";
import TemplateText from "./TemplateText";

interface DriftSectionProps {
  entries: DriftEntry[] | undefined;
  loading: boolean;
  window: string;
  onWindowChange: (window: string) => void;
}

const WINDOW_OPTIONS = ["15m", "1h", "6h", "24h"];
const Z_NOTABLE = 2; // |z| beyond this is visually flagged as a real deviation

export default function DriftSection({ entries, loading, window, onWindowChange }: DriftSectionProps) {
  return (
    <div className="rounded-lg border border-border bg-bg-panel">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-text">Frequency drift</h2>
          <p className="text-xs text-text-faint">
            Current-window rate vs. each template's own observed-lifetime baseline, by |z-score|.
          </p>
        </div>
        <div className="flex items-center gap-1">
          {WINDOW_OPTIONS.map((w) => (
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
      </div>

      {loading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : !entries || entries.length === 0 ? (
        <p className="p-4 text-sm text-text-faint">No templates observed in this window yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border text-xs uppercase tracking-wide text-text-faint">
                <th className="px-4 py-2 font-medium">Template</th>
                <th className="px-4 py-2 font-medium text-right">Baseline</th>
                <th className="px-4 py-2 font-medium text-right">Current</th>
                <th className="px-4 py-2 font-medium text-right">z-score</th>
              </tr>
            </thead>
            <tbody>
              {entries.slice(0, 15).map((e) => {
                const notable = e.z_score !== null && Math.abs(e.z_score) >= Z_NOTABLE;
                const rising = (e.z_score ?? 0) > 0;
                return (
                  <tr key={`${e.source_id}::${e.template_id}`} className="border-b border-border-subtle">
                    <td className="max-w-xs px-4 py-2.5">
                      <TemplateText template={e.template} className="block truncate" />
                      <span className="text-[11px] text-text-faint">{e.source_id}</span>
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-xs text-text-muted">
                      {e.baseline_rate_per_s.toFixed(3)}/s
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-xs text-text-muted">
                      {e.current_rate_per_s.toFixed(3)}/s ({formatCount(e.observed_in_window)})
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span
                        className={clsx(
                          "inline-flex items-center gap-1 font-mono text-sm font-semibold",
                          !notable ? "text-text-faint" : rising ? "text-status-bad" : "text-status-warn",
                        )}
                      >
                        {notable && (rising ? <TrendingUp className="h-3.5 w-3.5" /> : <TrendingDown className="h-3.5 w-3.5" />)}
                        {e.z_score !== null ? e.z_score.toFixed(2) : "—"}
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
