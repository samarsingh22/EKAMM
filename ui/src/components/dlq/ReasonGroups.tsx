import { Loader2, RotateCcw, Wand2 } from "lucide-react";
import clsx from "clsx";

import Skeleton from "../Skeleton";
import { formatCount } from "../../lib/format";

interface ReasonGroupsProps {
  byReason: Record<string, number> | undefined;
  total: number | undefined;
  unresolved: number | undefined;
  loading: boolean;
  activeReason: string | null;
  replayingReason: string | null;
  suggestingReason: string | null;
  onSelectReason: (reason: string | null) => void;
  onReplay: (reason: string) => void;
  onSuggest: (reason: string) => void;
}

export default function ReasonGroups({
  byReason,
  total,
  unresolved,
  loading,
  activeReason,
  replayingReason,
  suggestingReason,
  onSelectReason,
  onReplay,
  onSuggest,
}: ReasonGroupsProps) {
  const groups = Object.entries(byReason ?? {}).sort((a, b) => b[1] - a[1]);

  return (
    <div className="rounded-lg border border-border bg-bg-panel">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-text">By reason</h2>
          <p className="text-xs text-text-faint">
            {formatCount(total)} total · {formatCount(unresolved)} unresolved
          </p>
        </div>
        {activeReason && (
          <button
            type="button"
            onClick={() => onSelectReason(null)}
            className="text-xs text-accent hover:underline"
          >
            clear filter
          </button>
        )}
      </div>

      {loading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : groups.length === 0 ? (
        <p className="p-4 text-sm text-text-faint">No dead letters — every event has been processed.</p>
      ) : (
        <ul className="divide-y divide-border-subtle">
          {groups.map(([reason, count]) => {
            const replaying = replayingReason === reason;
            const suggesting = suggestingReason === reason;
            return (
              <li
                key={reason}
                className={clsx(
                  "flex flex-wrap items-center justify-between gap-3 px-4 py-3",
                  activeReason === reason && "bg-accent-bg",
                )}
              >
                <button
                  type="button"
                  onClick={() => onSelectReason(activeReason === reason ? null : reason)}
                  className="flex min-w-0 items-center gap-3 text-left"
                >
                  <span className="font-mono text-xl font-bold tabular-nums text-text">{count}</span>
                  <span className="truncate font-mono text-sm text-text-muted">{reason}</span>
                </button>

                <div className="flex shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => onSuggest(reason)}
                    disabled={suggesting}
                    className="flex items-center gap-1.5 rounded-md border border-accent px-2.5 py-1.5 text-xs font-semibold text-accent transition-colors hover:bg-accent-bg disabled:cursor-wait disabled:opacity-60"
                  >
                    {suggesting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Wand2 className="h-3.5 w-3.5" />}
                    Suggest parser for these
                  </button>
                  <button
                    type="button"
                    onClick={() => onReplay(reason)}
                    disabled={replaying}
                    className="flex items-center gap-1.5 rounded-md bg-accent px-2.5 py-1.5 text-xs font-semibold text-bg transition-colors hover:bg-accent/90 disabled:cursor-wait disabled:opacity-60"
                  >
                    {replaying ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />}
                    Replay
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
