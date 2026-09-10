import { useEffect, useRef, useState } from "react";

import { useIntegrityLedger, useIntegrityStatus, useVerifyChain, useVerifyEvents } from "../api/hooks";
import StatusBanner from "../components/integrity/StatusBanner";
import LedgerTable from "../components/integrity/LedgerTable";
import VerifyPanel, { type VerifyPhase } from "../components/integrity/VerifyPanel";

export default function Integrity() {
  const statusQuery = useIntegrityStatus(true);
  const ledgerQuery = useIntegrityLedger(true);
  const verifyChain = useVerifyChain();
  const verifyEvents = useVerifyEvents();

  const [phase, setPhase] = useState<VerifyPhase>("idle");
  const [progress, setProgress] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const running = phase === "chain" || phase === "events";

  // The verify endpoints are single blocking calls with no streaming progress,
  // so this bar shows real *phase* transitions (chain -> events) plus a smooth
  // time-estimated crawl within each phase, snapping to 100% on completion.
  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (!running) return;
    const ceiling = phase === "chain" ? 45 : 92;
    timerRef.current = setInterval(() => {
      setProgress((p) => (p < ceiling ? p + Math.max(0.5, (ceiling - p) * 0.08) : p));
    }, 120);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [running, phase]);

  const handleVerify = async () => {
    verifyChain.reset();
    verifyEvents.reset();
    setProgress(4);
    setPhase("chain");
    try {
      await verifyChain.mutateAsync();
    } catch {
      /* error surfaces via verifyChain.isError; still advance to events phase */
    }
    setProgress(50);
    setPhase("events");
    try {
      await verifyEvents.mutateAsync(undefined);
    } catch {
      /* error surfaces via verifyEvents.isError */
    }
    setProgress(100);
    setPhase("done");
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold text-text">Integrity</h1>
        <p className="text-sm text-text-faint">
          The signed Merkle ledger — tamper-evident proof that every stored event is the one that arrived.
        </p>
      </div>

      <StatusBanner status={statusQuery.data} chainReport={verifyChain.data} />

      <VerifyPanel
        phase={phase}
        progress={progress}
        running={running}
        chainReport={verifyChain.data}
        eventsReport={verifyEvents.data}
        onRun={handleVerify}
      />

      <LedgerTable entries={ledgerQuery.data} loading={ledgerQuery.isLoading} />
    </div>
  );
}
