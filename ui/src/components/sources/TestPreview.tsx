import { useState } from "react";
import { CheckCircle2, XCircle, MinusCircle } from "lucide-react";
import clsx from "clsx";

import type { SourceTestResponse, SourceTestResult } from "../../api/types";
import JsonTree from "../JsonTree";
import Skeleton from "../Skeleton";
import ScoreBar from "./ScoreBar";

interface TestPreviewProps {
  result: SourceTestResponse | undefined;
  loading: boolean;
  errorMessage: string | null;
  hasInput: boolean;
}

/**
 * Live "as you type" preview: runs `POST /sources/test` (debounced) and shows
 * the per-line parsed/matched outcome plus the aggregate suggestion score.
 */
export default function TestPreview({ result, loading, errorMessage, hasInput }: TestPreviewProps) {
  const [selected, setSelected] = useState(0);

  if (!hasInput) {
    return (
      <p className="p-4 text-sm text-text-faint">
        Paste sample lines above to see how this definition parses them.
      </p>
    );
  }

  if (errorMessage) {
    return <p className="p-4 text-sm text-status-bad">{errorMessage}</p>;
  }

  if (loading && !result) {
    return (
      <div className="space-y-3 p-4">
        <Skeleton className="h-16 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  if (!result) return null;

  const active: SourceTestResult | undefined = result.results[selected] ?? result.results[0];

  return (
    <div className={clsx("space-y-4 p-4 transition-opacity", loading && "opacity-60")}>
      <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
        <ScoreBar label="Parse rate" value={result.score.parse_rate} />
        <ScoreBar label="Completeness" value={result.score.completeness} />
        <ScoreBar label="Required fields" value={result.score.required_fields_covered} />
        <ScoreBar label="Confidence" value={result.score.confidence} />
      </div>

      <div className="flex flex-wrap gap-1.5">
        {result.results.map((r, i) => (
          <button
            key={i}
            type="button"
            onClick={() => setSelected(i)}
            className={clsx(
              "flex items-center gap-1 rounded-md border px-2 py-1 text-xs font-mono transition-colors",
              i === selected
                ? "border-accent bg-accent-bg text-accent"
                : "border-border text-text-muted hover:bg-bg-elevated",
            )}
            title={r.line}
          >
            {r.error ? (
              <XCircle className="h-3.5 w-3.5 text-status-bad" />
            ) : r.matched_detect ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-status-ok" />
            ) : (
              <MinusCircle className="h-3.5 w-3.5 text-text-faint" />
            )}
            line {i + 1}
          </button>
        ))}
        {result.results_truncated && (
          <span className="self-center text-xs text-text-faint">(showing first 50)</span>
        )}
      </div>

      {active && (
        <div className="space-y-2">
          <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-md border border-border bg-bg-inset p-2.5 font-mono text-xs text-text-muted">
            {active.line}
          </pre>

          {active.error ? (
            <p className="text-xs text-status-bad">{active.error}</p>
          ) : !active.matched_detect ? (
            <p className="text-xs text-text-faint">Did not match this definition's own detect rule.</p>
          ) : (
            <div className="flex items-center gap-3 text-xs text-text-muted">
              <span>completeness: {active.completeness !== null ? `${Math.round(active.completeness * 100)}%` : "—"}</span>
              <span>valid: {active.valid ? "yes" : "no"}</span>
            </div>
          )}

          {active.ocsf && (
            <div className="rounded-md border border-border bg-bg-inset p-3 font-mono text-xs leading-relaxed">
              <JsonTree data={active.ocsf} defaultExpandDepth={2} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
