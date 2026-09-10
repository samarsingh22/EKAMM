import { Loader2, Wand2 } from "lucide-react";
import clsx from "clsx";

import type { TemplateOut } from "../../api/types";
import Skeleton from "../Skeleton";
import { formatCount, formatDateTime, formatRelativeTime } from "../../lib/format";
import { templateKey } from "../../lib/templateSparkline";
import Sparkline from "./Sparkline";
import TemplateText from "./TemplateText";

interface TemplatesTableProps {
  templates: TemplateOut[] | undefined;
  loading: boolean;
  sparklines: Map<string, number[]>;
  generatingKey: string | null;
  onGenerateParser: (template: TemplateOut) => void;
}

export default function TemplatesTable({
  templates,
  loading,
  sparklines,
  generatingKey,
  onGenerateParser,
}: TemplatesTableProps) {
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-bg-panel">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-text">Mined templates</h2>
        <p className="text-xs text-text-faint">Every distinct shape Drain3 has learned, sorted by count.</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-text-faint">
              <th className="px-4 py-2 font-medium">Template</th>
              <th className="px-4 py-2 font-medium">Source</th>
              <th className="px-4 py-2 font-medium text-right">Count</th>
              <th className="px-4 py-2 font-medium">First seen</th>
              <th className="px-4 py-2 font-medium">Last seen</th>
              <th className="px-4 py-2 font-medium">Frequency</th>
              <th className="px-4 py-2 font-medium" />
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 8 }).map((_, i) => (
                <tr key={i} className="border-b border-border-subtle">
                  <td className="px-4 py-3" colSpan={7}>
                    <Skeleton className="h-4 w-full" />
                  </td>
                </tr>
              ))
            ) : !templates || templates.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-text-faint" colSpan={7}>
                  No templates mined yet.
                </td>
              </tr>
            ) : (
              templates.map((t) => {
                const key = templateKey(t);
                const generating = generatingKey === key;
                return (
                  <tr key={key} className="border-b border-border-subtle hover:bg-bg-elevated">
                    <td className="max-w-xs px-4 py-2.5">
                      <TemplateText template={t.template} className="block truncate" />
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted">{t.source_id}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-text">{formatCount(t.count)}</td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-xs text-text-muted" title={formatDateTime(t.first_seen_ns)}>
                      {formatRelativeTime(t.first_seen_ns)}
                    </td>
                    <td className="px-4 py-2.5 whitespace-nowrap text-xs text-text-muted" title={formatDateTime(t.last_seen_ns)}>
                      {formatRelativeTime(t.last_seen_ns)}
                    </td>
                    <td className="px-4 py-2.5">
                      <Sparkline values={sparklines.get(key) ?? []} />
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => onGenerateParser(t)}
                        disabled={generating}
                        className={clsx(
                          "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors",
                          generating
                            ? "cursor-wait border-border text-text-faint"
                            : "border-accent text-accent hover:bg-accent-bg",
                        )}
                      >
                        {generating ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <Wand2 className="h-3.5 w-3.5" />
                        )}
                        Generate
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
