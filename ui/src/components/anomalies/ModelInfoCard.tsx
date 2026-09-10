import { Boxes, CircleSlash2, CalendarClock, Cpu, Gauge } from "lucide-react";

import type { ModelInfo } from "../../api/types";
import Badge from "../Badge";
import Skeleton from "../Skeleton";
import { formatCount } from "../../lib/format";

interface ModelInfoCardProps {
  info: ModelInfo | undefined;
  loading: boolean;
}

function formatTrainedAt(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
}

function formatContamination(value: number | string | null): string {
  if (value === null || value === undefined) return "—";
  return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : value;
}

function Stat({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Cpu;
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-center gap-3">
      <Icon className="h-4 w-4 shrink-0 text-text-faint" />
      <div>
        <div className="text-[11px] uppercase tracking-wide text-text-faint">{label}</div>
        <div className="font-mono text-sm text-text">{value}</div>
      </div>
    </div>
  );
}

export default function ModelInfoCard({ info, loading }: ModelInfoCardProps) {
  if (loading) {
    return <Skeleton className="h-24 w-full rounded-lg" />;
  }

  const trained = info?.trained ?? false;

  return (
    <div className="rounded-lg border border-border bg-bg-panel p-4">
      <div className="mb-3 flex items-center gap-2">
        <Cpu className="h-4 w-4 text-accent" />
        <h2 className="text-sm font-semibold text-text">Anomaly model</h2>
        <Badge tone={trained ? "ok" : "bad"}>{trained ? "TRAINED" : "NOT TRAINED"}</Badge>
      </div>

      {trained ? (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Stat icon={CalendarClock} label="Trained at" value={formatTrainedAt(info?.trained_at ?? null)} />
          <Stat icon={Boxes} label="Training samples" value={formatCount(info?.n_samples ?? null)} />
          <Stat
            icon={Gauge}
            label="Contamination"
            value={formatContamination(info?.contamination ?? null)}
          />
          <Stat icon={Cpu} label="Features" value={formatCount(info?.n_features ?? null)} />
        </div>
      ) : (
        <div className="flex items-center gap-2 text-sm text-text-faint">
          <CircleSlash2 className="h-4 w-4" />
          No model has been trained yet — run{" "}
          <code className="text-text-muted">ulpf ml train --date-from … --date-to …</code>.
        </div>
      )}
    </div>
  );
}
