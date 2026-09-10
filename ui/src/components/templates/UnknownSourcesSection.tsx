import { AlertCircle, Loader2, Wand2 } from "lucide-react";
import clsx from "clsx";

import type { TemplateOut } from "../../api/types";
import Skeleton from "../Skeleton";
import { formatCount, formatRelativeTime } from "../../lib/format";
import TemplateText from "./TemplateText";

const TOP_N = 5;

interface UnknownSourcesSectionProps {
  templates: TemplateOut[] | undefined;
  loading: boolean;
  generatingKey: string | null;
  onGenerateParser: (template: TemplateOut) => void;
}

/**
 * The onboarding worklist: templates from traffic no source YAML understands
 * yet, worst offenders first. This is requirement (i)'s "before" state —
 * "Generate Parser" is the one-click path to the "after".
 */
export default function UnknownSourcesSection({
  templates,
  loading,
  generatingKey,
  onGenerateParser,
}: UnknownSourcesSectionProps) {
  const top = (templates ?? []).slice(0, TOP_N);

  return (
    <div className="rounded-lg border border-status-warn/30 bg-bg-panel">
      <div className="flex items-center gap-2 border-b border-status-warn/30 bg-status-warn/10 px-4 py-3">
        <AlertCircle className="h-5 w-5 text-status-warn" strokeWidth={2} />
        <div>
          <h2 className="text-sm font-semibold text-text">Unknown Sources</h2>
          <p className="text-xs text-text-faint">
            Traffic no source definition matches yet — ordered by event count.
          </p>
        </div>
      </div>

      {loading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : top.length === 0 ? (
        <p className="p-4 text-sm text-text-faint">
          Nothing unmatched right now — every observed shape has a source definition.
        </p>
      ) : (
        <ul className="divide-y divide-border-subtle">
          {top.map((t) => {
            const key = `${t.source_id}::${t.template_id}`;
            const generating = generatingKey === key;
            return (
              <li key={key} className="flex items-center justify-between gap-4 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <TemplateText template={t.template} className="block truncate" />
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-text-faint">
                    <span className="font-mono">{t.source_id}</span>
                    <span>{formatCount(t.count)} events</span>
                    <span>last seen {formatRelativeTime(t.last_seen_ns)}</span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => onGenerateParser(t)}
                  disabled={generating}
                  className={clsx(
                    "flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-sm font-semibold transition-colors",
                    generating
                      ? "cursor-wait bg-bg-elevated text-text-faint"
                      : "bg-accent text-bg hover:bg-accent/90",
                  )}
                >
                  {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />}
                  Generate Parser
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
