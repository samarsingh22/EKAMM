import { AlertOctagon, CheckCircle2, Play } from "lucide-react";
import clsx from "clsx";

import type { ChainVerifyReport, EventsVerifyReport } from "../../api/types";
import { formatCount } from "../../lib/format";

export type VerifyPhase = "idle" | "chain" | "events" | "done";

interface VerifyPanelProps {
  phase: VerifyPhase;
  progress: number; // 0..100
  running: boolean;
  chainReport: ChainVerifyReport | undefined;
  eventsReport: EventsVerifyReport | undefined;
  onRun: () => void;
}

const PHASE_LABEL: Record<VerifyPhase, string> = {
  idle: "",
  chain: "Recomputing every chained root and checking signatures…",
  events: "Re-hashing every raw event and verifying its Merkle proof…",
  done: "Verification complete.",
};

export default function VerifyPanel({
  phase,
  progress,
  running,
  chainReport,
  eventsReport,
  onRun,
}: VerifyPanelProps) {
  const eventsFailed = eventsReport && eventsReport.failed > 0;
  const chainBroken = chainReport && !chainReport.ok;
  const anyFailure = Boolean(eventsFailed || chainBroken);

  return (
    <div
      className={clsx(
        "rounded-lg border bg-bg-panel p-4",
        anyFailure ? "border-status-bad" : "border-border",
      )}
    >
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-text">Full verification</h2>
          <p className="text-xs text-text-faint">
            Independently re-derives the chain and every event's inclusion proof from the stored evidence.
          </p>
        </div>
        <button
          type="button"
          onClick={onRun}
          disabled={running}
          className={clsx(
            "flex shrink-0 items-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition-colors",
            running ? "cursor-wait bg-bg-elevated text-text-faint" : "bg-accent text-bg hover:bg-accent/90",
          )}
        >
          <Play className="h-4 w-4" strokeWidth={2.5} />
          {running ? "Verifying…" : "Verify Now"}
        </button>
      </div>

      {(running || phase === "done") && (
        <div className="mt-4">
          <div className="mb-1 flex justify-between text-xs text-text-muted">
            <span>{PHASE_LABEL[phase]}</span>
            <span className="font-mono">{Math.round(progress)}%</span>
          </div>
          <div className="h-2 w-full overflow-hidden rounded-full bg-bg-inset">
            <div
              className={clsx(
                "h-full rounded-full transition-all duration-300",
                anyFailure ? "bg-status-bad" : "bg-accent",
              )}
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      )}

      {(chainReport || eventsReport) && (
        <div className="mt-4 space-y-3">
          {chainReport && (
            <ResultRow
              ok={chainReport.ok}
              label="Chain"
              detail={
                chainReport.ok
                  ? `${formatCount(chainReport.checked)} entries checked · head ${chainReport.head_hex.slice(0, 12)}…`
                  : `broken at sequence ${chainReport.broken_at} — ${chainReport.broken_reason ?? ""}`
              }
            />
          )}
          {eventsReport && (
            <ResultRow
              ok={eventsReport.failed === 0}
              label="Events"
              detail={`${formatCount(eventsReport.passed)} passed · ${formatCount(eventsReport.failed)} failed of ${formatCount(eventsReport.checked)}`}
            />
          )}

          {eventsFailed && (
            <div className="rounded-md border-2 border-status-bad bg-status-bad/15 p-3">
              <div className="flex items-center gap-2 text-sm font-bold uppercase text-status-bad">
                <AlertOctagon className="h-4 w-4" />
                {eventsReport!.failed} event{eventsReport!.failed === 1 ? "" : "s"} failed verification
              </div>
              <ul className="mt-2 space-y-1">
                {eventsReport!.failures.map((f) => (
                  <li key={f.event_uid} className="font-mono text-xs text-status-bad">
                    {f.event_uid} — {f.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ResultRow({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  return (
    <div className="flex items-start gap-2 text-sm">
      {ok ? (
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-status-ok" />
      ) : (
        <AlertOctagon className="mt-0.5 h-4 w-4 shrink-0 text-status-bad" />
      )}
      <div>
        <span className={clsx("font-semibold", ok ? "text-text" : "text-status-bad")}>{label}</span>{" "}
        <span className={clsx(ok ? "text-text-muted" : "text-status-bad/90")}>{detail}</span>
      </div>
    </div>
  );
}
