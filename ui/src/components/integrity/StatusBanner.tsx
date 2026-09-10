import { ShieldCheck, ShieldX, ShieldQuestion } from "lucide-react";
import clsx from "clsx";

import type { ChainVerifyReport, IntegrityStatus } from "../../api/types";
import { formatCount, formatDateTime } from "../../lib/format";

interface StatusBannerProps {
  status: IntegrityStatus | undefined;
  chainReport: ChainVerifyReport | undefined;
}

type Verdict =
  | { kind: "verified" }
  | { kind: "broken"; seq: number | null; reason: string | null }
  | { kind: "no-ledger" }
  | { kind: "unknown" };

function computeVerdict(status: IntegrityStatus | undefined, chainReport: ChainVerifyReport | undefined): Verdict {
  if (chainReport && !chainReport.ok) {
    return { kind: "broken", seq: chainReport.broken_at, reason: chainReport.broken_reason };
  }
  if (chainReport && !chainReport.ledger_present) return { kind: "no-ledger" };
  if (status) {
    if (status.ledger_entries === 0) return { kind: "no-ledger" };
    if (!status.chain_verified) return { kind: "broken", seq: null, reason: null };
    return { kind: "verified" };
  }
  return { kind: "unknown" };
}

export default function StatusBanner({ status, chainReport }: StatusBannerProps) {
  const verdict = computeVerdict(status, chainReport);

  if (verdict.kind === "broken") {
    return (
      <div className="animate-pulse rounded-lg border-4 border-status-bad bg-status-bad/15 p-6">
        <div className="flex items-center gap-4">
          <ShieldX className="h-14 w-14 shrink-0 text-status-bad" strokeWidth={2.5} />
          <div>
            <div className="text-3xl font-black uppercase tracking-tight text-status-bad">
              {verdict.seq !== null ? `Chain broken at sequence ${verdict.seq}` : "Chain broken"}
            </div>
            <div className="mt-1 text-sm text-status-bad/90">
              {verdict.reason ?? "The signed ledger no longer verifies. The evidence chain has been tampered with."}
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (verdict.kind === "no-ledger") {
    return (
      <Banner
        icon={ShieldQuestion}
        tone="muted"
        title="No integrity ledger"
        subtitle="Signing is not configured — events are hashed but not sealed into a signed chain."
      />
    );
  }

  if (verdict.kind === "unknown") {
    return <Banner icon={ShieldQuestion} tone="muted" title="Checking integrity…" subtitle="" />;
  }

  return (
    <Banner
      icon={ShieldCheck}
      tone="ok"
      title="Chain verified"
      subtitle={
        status
          ? `${formatCount(status.ledger_entries)} sealed batches · ${formatCount(
              status.total_events_sealed,
            )} events · last seal ${formatDateTime(status.last_seal_ns)}`
          : ""
      }
    />
  );
}

function Banner({
  icon: Icon,
  tone,
  title,
  subtitle,
}: {
  icon: typeof ShieldCheck;
  tone: "ok" | "muted";
  title: string;
  subtitle: string;
}) {
  return (
    <div
      className={clsx(
        "rounded-lg border-2 p-6",
        tone === "ok" ? "border-status-ok/50 bg-status-ok/10" : "border-border bg-bg-panel",
      )}
    >
      <div className="flex items-center gap-4">
        <Icon
          className={clsx("h-14 w-14 shrink-0", tone === "ok" ? "text-status-ok" : "text-text-muted")}
          strokeWidth={2.5}
        />
        <div>
          <div
            className={clsx(
              "text-3xl font-black uppercase tracking-tight",
              tone === "ok" ? "text-status-ok" : "text-text",
            )}
          >
            {title}
          </div>
          {subtitle && <div className="mt-1 text-sm text-text-muted">{subtitle}</div>}
        </div>
      </div>
    </div>
  );
}
