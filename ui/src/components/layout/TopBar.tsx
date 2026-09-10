import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { RefreshCw, Wifi, WifiOff } from "lucide-react";

import { useLiveStats, useSourcesReloadStatus } from "../../api/hooks";
import { formatEps, formatPercent } from "../../lib/format";

export default function TopBar() {
  const { eps, parseSuccessRate, isError, isSuccess } = useLiveStats();

  const connectionLabel = isError ? "disconnected" : isSuccess ? "live" : "connecting…";
  const dotColor = isError ? "bg-status-bad" : isSuccess ? "bg-status-ok" : "bg-status-warn";

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-bg-panel px-6">
      <div>
        <h1 className="text-sm font-medium text-text-muted">Perimeter log pipeline</h1>
      </div>

      <div className="flex items-center gap-6 text-sm">
        <Stat label="EPS" value={formatEps(eps)} />
        <Stat label="parse success" value={formatPercent(parseSuccessRate)} />
        <ReloadCounter />

        <div className="flex items-center gap-2 rounded-full border border-border bg-bg px-3 py-1">
          <span className={clsx("status-dot", dotColor, isSuccess && "animate-pulse")} />
          {isError ? (
            <WifiOff className="h-3.5 w-3.5 text-status-bad" strokeWidth={2} />
          ) : (
            <Wifi className="h-3.5 w-3.5 text-text-muted" strokeWidth={2} />
          )}
          <span className="text-xs text-text-muted">{connectionLabel}</span>
        </div>
      </div>
    </header>
  );
}

/**
 * Source hot-reload counter — the visible proof that "Save & Activate"
 * changed the running system with no restart. Polls live; flashes accent
 * and briefly scales up on every increment, so it can't be missed on camera.
 */
function ReloadCounter() {
  const { data } = useSourcesReloadStatus(true);
  const [flash, setFlash] = useState(false);
  const previous = useRef<number | null>(null);

  useEffect(() => {
    if (data === undefined) return;
    if (previous.current !== null && data.reload_count > previous.current) {
      setFlash(true);
      const id = setTimeout(() => setFlash(false), 900);
      previous.current = data.reload_count;
      return () => clearTimeout(id);
    }
    previous.current = data.reload_count;
  }, [data]);

  return (
    <div
      className={clsx(
        "flex items-center gap-1.5 rounded-full border px-3 py-1 transition-all duration-300",
        flash ? "scale-110 border-accent animate-flash-accent" : "border-border",
      )}
      title="Source definition reloads since startup"
    >
      <RefreshCw className={clsx("h-3.5 w-3.5", flash ? "text-accent" : "text-text-faint")} strokeWidth={2} />
      <span className={clsx("font-mono text-base font-semibold", flash ? "text-accent" : "text-text")}>
        {data?.reload_count ?? "—"}
      </span>
      <span className="text-xs uppercase tracking-wide text-text-faint">reloads</span>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="font-mono text-base font-semibold text-text">{value}</span>
      <span className="text-xs uppercase tracking-wide text-text-faint">{label}</span>
    </div>
  );
}
