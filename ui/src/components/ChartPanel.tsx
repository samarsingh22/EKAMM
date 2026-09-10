import type { PropsWithChildren, ReactNode } from "react";

import Skeleton from "./Skeleton";

interface ChartPanelProps {
  title: string;
  subtitle?: string;
  loading?: boolean;
  height?: number;
  actions?: ReactNode;
}

/** Titled card wrapping one chart, with a same-sized skeleton while data loads. */
export default function ChartPanel({
  title,
  subtitle,
  loading,
  height = 280,
  actions,
  children,
}: PropsWithChildren<ChartPanelProps>) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border bg-bg-panel p-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-text">{title}</h2>
          {subtitle && <p className="text-xs text-text-faint">{subtitle}</p>}
        </div>
        {actions}
      </div>
      {loading ? <Skeleton style={{ height }} className="w-full" /> : <div style={{ height }}>{children}</div>}
    </div>
  );
}
