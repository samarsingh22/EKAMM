import { Pencil } from "lucide-react";

import type { SourceListItem } from "../../api/types";
import Badge from "../Badge";
import { formatClockTime, formatCount, formatPercent } from "../../lib/format";

interface SourceCardProps {
  source: SourceListItem;
  onClick: () => void;
}

export default function SourceCard({ source, onClick }: SourceCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group flex flex-col gap-3 rounded-lg border border-border bg-bg-panel p-4 text-left transition-colors hover:border-accent/60 hover:bg-bg-elevated"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-mono text-sm font-semibold text-text">{source.name}</div>
          <div className="truncate text-xs text-text-faint">
            {source.vendor} · {source.product}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Badge tone={source.enabled ? "ok" : "muted"}>{source.enabled ? "enabled" : "disabled"}</Badge>
          <Pencil className="h-3.5 w-3.5 text-text-faint opacity-0 transition-opacity group-hover:opacity-100" />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs">
        <Stat label="Events seen" value={formatCount(source.events_seen)} />
        <Stat label="Last event" value={formatClockTime(source.last_event_ns)} />
        <Stat label="Parse rate" value={formatPercent(source.parse_rate)} tone={rateTone(source.parse_rate)} />
        <Stat
          label="Completeness"
          value={formatPercent(source.avg_completeness)}
          tone={rateTone(source.avg_completeness)}
        />
      </div>
    </button>
  );
}

function rateTone(value: number | null): "ok" | "warn" | "bad" | undefined {
  if (value === null) return undefined;
  if (value >= 0.9) return "ok";
  if (value >= 0.6) return "warn";
  return "bad";
}

const TONE_TEXT: Record<"ok" | "warn" | "bad", string> = {
  ok: "text-status-ok",
  warn: "text-status-warn",
  bad: "text-status-bad",
};

function Stat({ label, value, tone }: { label: string; value: string; tone?: "ok" | "warn" | "bad" }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-text-faint">{label}</div>
      <div className={`font-mono text-sm font-medium ${tone ? TONE_TEXT[tone] : "text-text"}`}>{value}</div>
    </div>
  );
}
