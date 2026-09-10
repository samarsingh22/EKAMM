import { CheckCircle2, XCircle } from "lucide-react";
import clsx from "clsx";

import type { LedgerEntryRow } from "../../api/types";
import Skeleton from "../Skeleton";
import { formatCount, formatDateTime } from "../../lib/format";

function truncateHex(hex: string, head = 12, tail = 6): string {
  return hex.length <= head + tail + 1 ? hex : `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

export default function LedgerTable({
  entries,
  loading,
}: {
  entries: LedgerEntryRow[] | undefined;
  loading: boolean;
}) {
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-bg-panel">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-text">Signed ledger</h2>
        <p className="text-xs text-text-faint">One entry per sealed batch, hash-chained and Ed25519-signed.</p>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border text-xs uppercase tracking-wide text-text-faint">
              <th className="px-4 py-2 font-medium text-right">Seq</th>
              <th className="px-4 py-2 font-medium">Sealed at</th>
              <th className="px-4 py-2 font-medium text-right">Leaves</th>
              <th className="px-4 py-2 font-medium">Batch root</th>
              <th className="px-4 py-2 font-medium">Signature</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i} className="border-b border-border-subtle">
                  <td className="px-4 py-3" colSpan={5}>
                    <Skeleton className="h-4 w-full" />
                  </td>
                </tr>
              ))
            ) : !entries || entries.length === 0 ? (
              <tr>
                <td className="px-4 py-8 text-center text-text-faint" colSpan={5}>
                  No sealed batches yet.
                </td>
              </tr>
            ) : (
              entries.map((e) => (
                <tr
                  key={e.seq}
                  className={clsx(
                    "border-b border-border-subtle",
                    !e.verified && "bg-status-bad/10",
                  )}
                >
                  <td className="px-4 py-2.5 text-right font-mono text-text">{e.seq}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap text-xs text-text-muted">
                    {formatDateTime(e.sealed_at_ns)}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-text-muted">
                    {formatCount(e.leaf_count)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-text-muted" title={e.batch_root}>
                    {truncateHex(e.batch_root)}
                  </td>
                  <td className="px-4 py-2.5">
                    {e.verified ? (
                      <span className="inline-flex items-center gap-1 text-xs font-medium text-status-ok">
                        <CheckCircle2 className="h-3.5 w-3.5" /> valid
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-xs font-semibold text-status-bad">
                        <XCircle className="h-3.5 w-3.5" />
                        {e.signature_ok ? "chain link broken" : "invalid"}
                      </span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
