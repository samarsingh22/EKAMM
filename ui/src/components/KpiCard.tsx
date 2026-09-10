import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import clsx from "clsx";

import Skeleton from "./Skeleton";

interface KpiCardProps {
  label: string;
  icon: LucideIcon;
  loading?: boolean;
  /** The big, legible figure — a string so callers control formatting (units, decimals, "—"). */
  value?: ReactNode;
  /** Small line under the value, e.g. a count or a qualifier. */
  sub?: ReactNode;
  tone?: "default" | "ok" | "warn" | "bad";
  /** Set false for a non-numeric value (e.g. a status badge) that shouldn't get giant number styling. */
  large?: boolean;
}

/**
 * One top-row KPI tile. Value text is deliberately huge (`text-4xl`+) and
 * `tabular-nums` so digits don't jitter between polls — this row is the
 * thing a judge glances at from across a room.
 */
export default function KpiCard({
  label,
  icon: Icon,
  loading,
  value,
  sub,
  tone = "default",
  large = true,
}: KpiCardProps) {
  const toneClass =
    tone === "ok"
      ? "text-status-ok"
      : tone === "warn"
        ? "text-status-warn"
        : tone === "bad"
          ? "text-status-bad"
          : "text-text";

  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border bg-bg-panel p-4">
      <div className="flex items-center gap-2 text-text-muted">
        <Icon className="h-4 w-4" strokeWidth={2} />
        <span className="text-xs font-medium uppercase tracking-wider">{label}</span>
      </div>

      {loading ? (
        <Skeleton className="h-10 w-24" />
      ) : large ? (
        <div className={clsx("font-mono text-4xl font-bold leading-none tabular-nums", toneClass)}>
          {value}
        </div>
      ) : (
        <div className="flex h-10 items-center">{value}</div>
      )}

      <div className="h-4 text-xs text-text-faint">{!loading && sub}</div>
    </div>
  );
}
