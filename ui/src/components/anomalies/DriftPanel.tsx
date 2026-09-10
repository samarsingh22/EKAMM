import { TrendingDown, TrendingUp } from "lucide-react";
import clsx from "clsx";

import type { TemplateDriftSignal } from "../../api/types";
import Skeleton from "../Skeleton";
import TemplateText from "../templates/TemplateText";

interface DriftPanelProps {
  signals: TemplateDriftSignal[] | undefined;
  loading: boolean;
  windowMinutes: number;
  onWindowChange: (minutes: number) => void;
}

const WINDOW_OPTIONS = [1, 5, 15, 60];

function rate(perMinute: number): string {
  return `${perMinute.toFixed(perMinute < 10 ? 2 : 0)}/min`;
}

function DriftRow({ signal }: { signal: TemplateDriftSignal }) {
  const dropping = signal.direction === "drop";
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border-subtle px-4 py-3 last:border-b-0">
      <div className="min-w-0">
        <TemplateText template={signal.template} className="block truncate" />
        <div className="mt-0.5 text-[11px] text-text-faint">
          {signal.source_id} · baseline {rate(signal.baseline_rate)} → now {rate(signal.current_rate)}{" "}
          · seen {signal.observed} vs expected {signal.expected.toFixed(1)}
        </div>
      </div>
      <div
        className={clsx(
          "flex shrink-0 items-center gap-1 font-mono text-sm font-semibold",
          dropping ? "text-status-bad" : "text-status-warn",
        )}
      >
        {dropping ? <TrendingDown className="h-4 w-4" /> : <TrendingUp className="h-4 w-4" />}
        z {signal.z_score.toFixed(1)}
      </div>
    </div>
  );
}

function Section({
  title,
  hint,
  signals,
  loading,
  emptyText,
}: {
  title: string;
  hint: string;
  signals: TemplateDriftSignal[];
  loading: boolean;
  emptyText: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-bg-panel">
      <div className="border-b border-border px-4 py-3">
        <h3 className="text-sm font-semibold text-text">{title}</h3>
        <p className="text-xs text-text-faint">{hint}</p>
      </div>
      {loading ? (
        <div className="space-y-2 p-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : signals.length === 0 ? (
        <p className="p-4 text-sm text-text-faint">{emptyText}</p>
      ) : (
        <div>
          {signals.map((s) => (
            <DriftRow key={`${s.source_id}::${s.template_id}`} signal={s} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function DriftPanel({
  signals,
  loading,
  windowMinutes,
  onWindowChange,
}: DriftPanelProps) {
  const spiking = (signals ?? [])
    .filter((s) => s.direction === "spike")
    .sort((a, b) => b.z_score - a.z_score);
  const silent = (signals ?? [])
    .filter((s) => s.direction === "drop")
    .sort((a, b) => a.z_score - b.z_score);

  return (
    <div className="space-y-3">
      <div className="flex items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-text">Template drift</h2>
          <p className="text-xs text-text-faint">
            Each mined template's current rate vs. its own exponentially-weighted baseline. A common
            template dropping to zero is a logging failure — or an attacker turning logs off.
          </p>
        </div>
        <div className="flex items-center gap-1">
          {WINDOW_OPTIONS.map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => onWindowChange(m)}
              className={clsx(
                "rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
                m === windowMinutes
                  ? "bg-accent-bg text-accent"
                  : "text-text-muted hover:bg-bg-elevated",
              )}
            >
              {m}m
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Section
          title="Silent — dropping to zero"
          hint="Established templates that have gone quiet. Invisible to volume monitoring."
          signals={silent}
          loading={loading}
          emptyText="No templates have gone silent in this window."
        />
        <Section
          title="Spiking"
          hint="Rare templates suddenly firing far above baseline — a new pattern or a misconfiguration."
          signals={spiking}
          loading={loading}
          emptyText="No templates are spiking in this window."
        />
      </div>
    </div>
  );
}
