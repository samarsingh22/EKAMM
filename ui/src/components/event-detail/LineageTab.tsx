import { useEffect, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  FileText,
  Hash,
  GitCommitVertical,
  BookMarked,
  Link2,
  Loader2,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import clsx from "clsx";

import { useEventLineage, useEventProof } from "../../api/hooks";
import Badge from "../Badge";
import JsonTree from "../JsonTree";
import Skeleton from "../Skeleton";
import type { Tone } from "../../lib/ocsf";

function shortHex(value: string | null | undefined, head = 10, tail = 6): string {
  if (!value) return "—";
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

interface ChainNode {
  icon: LucideIcon;
  title: string;
  value: string;
  tone: Tone;
  statusLabel?: string;
}

export default function LineageTab({ eventUid }: { eventUid: string }) {
  const lineage = useEventLineage(eventUid);
  const proof = useEventProof(eventUid);
  const [verifyRequested, setVerifyRequested] = useState(false);

  // reset the on-demand proof state if the panel is reopened on a different event
  useEffect(() => {
    setVerifyRequested(false);
  }, [eventUid]);

  if (lineage.isLoading) {
    return (
      <div className="space-y-4 p-4">
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }

  const data = lineage.data;
  if (!data) {
    return <p className="p-4 text-sm text-text-faint">Lineage unavailable.</p>;
  }

  const nodes: ChainNode[] = [
    { icon: FileText, title: "Raw Event", value: shortHex(eventUid, 8, 4), tone: "muted" },
    {
      icon: Hash,
      title: "[hash]",
      value: shortHex(data.raw_hash),
      tone: data.raw_verified ? "ok" : "bad",
      statusLabel: data.raw_verified ? "matches" : "mismatch",
    },
    {
      icon: GitCommitVertical,
      title: "Merkle Leaf",
      value: `${data.merkle_proof.length} step${data.merkle_proof.length === 1 ? "" : "s"}`,
      tone: data.merkle_proof.length > 0 ? "ok" : "muted",
    },
    {
      icon: BookMarked,
      title: "Ledger Entry",
      value: data.ledger_seq !== null ? `#${data.ledger_seq}` : "not sealed",
      tone: data.ledger_seq !== null ? "ok" : "muted",
    },
    {
      icon: Link2,
      title: "Chained Root",
      value: data.ledger_verified ? "verified" : "unverified",
      tone: data.ledger_verified ? "ok" : "bad",
    },
  ];

  const handleVerify = () => {
    setVerifyRequested(true);
    void proof.refetch();
  };

  return (
    <div className="space-y-6 p-4">
      {/* the chain */}
      <div className="flex flex-wrap items-stretch gap-2 overflow-x-auto rounded-lg border border-border bg-bg-inset p-4">
        {nodes.map((node, i) => (
          <ChainNodeCard key={node.title} node={node} last={i === nodes.length - 1} />
        ))}
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Field label="Event UID" value={eventUid} mono />
        <Field label="Source" value={data.source_type ?? "—"} />
        <Field label="Mapping version" value={data.mapping_version ?? "—"} />
      </div>

      {data.merkle_proof.length > 0 && (
        <details className="rounded-lg border border-border bg-bg-inset p-3">
          <summary className="cursor-pointer text-sm font-medium text-text-muted">
            Merkle authentication path ({data.merkle_proof.length} steps)
          </summary>
          <ol className="mt-3 space-y-1">
            {data.merkle_proof.map((step, i) => (
              <li key={i} className="flex items-center gap-2 font-mono text-xs text-text-muted">
                <span className="w-6 text-right text-text-faint">{i}.</span>
                <Badge tone="muted">{step.side}</Badge>
                <span className="truncate">{step.sibling}</span>
              </li>
            ))}
          </ol>
        </details>
      )}

      {/* on-demand full proof verification */}
      <div className="rounded-lg border border-border bg-bg-inset p-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-text">Full verification</h3>
            <p className="text-xs text-text-faint">
              Re-hashes the stored bytes and re-checks the Merkle proof + ledger signature, live.
            </p>
          </div>
          <button
            type="button"
            onClick={handleVerify}
            disabled={proof.isFetching}
            className={clsx(
              "flex shrink-0 items-center gap-2 rounded-md border px-4 py-2 text-sm font-medium transition-colors",
              "border-accent text-accent hover:bg-accent-bg disabled:cursor-not-allowed disabled:opacity-60",
            )}
          >
            {proof.isFetching ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : proof.data?.ok ? (
              <ShieldCheck className="h-4 w-4" />
            ) : proof.data ? (
              <ShieldX className="h-4 w-4" />
            ) : null}
            {proof.isFetching ? "Verifying…" : "Verify this event"}
          </button>
        </div>

        {verifyRequested && !proof.isFetching && (
          <div className="mt-4 space-y-3">
            {proof.isError || !proof.data ? (
              <p className="text-sm text-status-bad">Verification request failed.</p>
            ) : (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={proof.data.ok ? "ok" : "bad"}>
                    {proof.data.ok ? "ALL CHECKS PASSED" : "VERIFICATION FAILED"}
                  </Badge>
                  <Badge tone={proof.data.hash_ok ? "ok" : "bad"}>hash {proof.data.hash_ok ? "ok" : "bad"}</Badge>
                  <Badge tone={proof.data.proof_ok ? "ok" : "bad"}>
                    proof {proof.data.proof_ok ? "ok" : "bad"}
                  </Badge>
                  <Badge tone={proof.data.signature_ok ? "ok" : "bad"}>
                    signature {proof.data.signature_ok ? "ok" : "bad"}
                  </Badge>
                </div>
                {proof.data.ledger_entry && (
                  <div className="rounded-md border border-border bg-bg p-3 font-mono text-xs">
                    <JsonTree data={proof.data.ledger_entry} defaultExpandDepth={1} />
                  </div>
                )}
                {proof.data.reason && <p className="text-xs text-text-faint">{proof.data.reason}</p>}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ChainNodeCard({ node, last }: { node: ChainNode; last: boolean }) {
  const Icon = node.icon;
  const toneClass =
    node.tone === "ok"
      ? "border-status-ok/40 text-status-ok"
      : node.tone === "bad"
        ? "border-status-bad/40 text-status-bad"
        : node.tone === "warn"
          ? "border-status-warn/40 text-status-warn"
          : "border-border text-text-muted";

  return (
    <div className="flex items-center gap-2">
      <div className={clsx("flex min-w-[9.5rem] flex-col items-center gap-1 rounded-lg border bg-bg-panel px-3 py-3", toneClass)}>
        <Icon className="h-5 w-5" strokeWidth={2} />
        <div className="text-[11px] font-medium uppercase tracking-wide text-text-faint">{node.title}</div>
        <div className="max-w-[9rem] truncate font-mono text-xs text-text" title={node.value}>
          {node.value}
        </div>
        {node.statusLabel && <div className="text-[10px] uppercase tracking-wide">{node.statusLabel}</div>}
      </div>
      {!last && <div className="h-px w-4 shrink-0 bg-border sm:w-6" aria-hidden />}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-[11px] uppercase tracking-wide text-text-faint">{label}</div>
      <div className={`truncate text-sm text-text ${mono ? "font-mono" : ""}`} title={value}>
        {value}
      </div>
    </div>
  );
}
