import { useState } from "react";
import { FileText, Braces } from "lucide-react";

import { useEventDetail, useEventRaw } from "../../api/hooks";
import Badge from "../Badge";
import JsonTree from "../JsonTree";
import LinkChip from "../LinkChip";
import Skeleton from "../Skeleton";

type LinkKind = "hash" | "uid" | null;

/**
 * Raw evidence on the left, the normalized OCSF record on the right — the
 * demo's headline shot. `metadata.log_hash`/`metadata.uid` (stamped into
 * every OCSF record for exactly this purpose — see requirement d) are each
 * paired with their raw-side counterpart (`raw_hash`, `event_uid`) via
 * {@link LinkChip}: hovering either lights up both.
 */
export default function SplitView({ eventUid }: { eventUid: string }) {
  const raw = useEventRaw(eventUid);
  const normalized = useEventDetail(eventUid);
  const [hovered, setHovered] = useState<LinkKind>(null);

  const metadata = (normalized.data?.metadata as Record<string, unknown> | undefined) ?? undefined;
  const metaUid = typeof metadata?.uid === "string" ? metadata.uid : undefined;
  const metaHash = typeof metadata?.log_hash === "string" ? metadata.log_hash : undefined;

  return (
    <div className="grid h-full min-h-0 grid-cols-1 divide-y divide-border md:grid-cols-2 md:divide-x md:divide-y-0">
      {/* raw */}
      <div className="flex min-h-0 flex-col">
        <PaneHeader icon={FileText} title="Raw Event" tone="muted" />
        <div className="min-h-0 flex-1 overflow-y-auto p-4">
          {raw.isLoading ? (
            <SplitSkeleton />
          ) : raw.data ? (
            <div className="space-y-3">
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-bg-inset p-3 font-mono text-xs leading-relaxed text-text">
                {raw.data.raw_text}
              </pre>
              <div className="space-y-2">
                <LinkChip
                  label="raw_hash"
                  value={raw.data.raw_hash}
                  active={hovered === "hash"}
                  onHover={(h) => setHovered(h ? "hash" : null)}
                />
                <LinkChip
                  label="event_uid"
                  value={raw.data.event_uid}
                  active={hovered === "uid"}
                  onHover={(h) => setHovered(h ? "uid" : null)}
                />
              </div>
              <Badge tone={raw.data.verified ? "ok" : "bad"}>
                {raw.data.verified ? "verified" : "verification failed"}
              </Badge>
            </div>
          ) : (
            <EmptyNote text="Raw event unavailable." />
          )}
        </div>
      </div>

      {/* normalized */}
      <div className="flex min-h-0 flex-col">
        <PaneHeader icon={Braces} title="Normalized (OCSF)" tone="accent" />
        <div className="min-h-0 flex-1 overflow-y-auto p-4">
          {normalized.isLoading ? (
            <SplitSkeleton />
          ) : normalized.data ? (
            <div className="space-y-3">
              <div className="space-y-2">
                <LinkChip
                  label="metadata.log_hash"
                  value={metaHash}
                  active={hovered === "hash"}
                  onHover={(h) => setHovered(h ? "hash" : null)}
                />
                <LinkChip
                  label="metadata.uid"
                  value={metaUid}
                  active={hovered === "uid"}
                  onHover={(h) => setHovered(h ? "uid" : null)}
                />
              </div>
              <div className="rounded-md border border-border bg-bg-inset p-3 font-mono text-xs leading-relaxed">
                <JsonTree data={normalized.data} defaultExpandDepth={2} />
              </div>
            </div>
          ) : (
            <EmptyNote text="Normalized record unavailable." />
          )}
        </div>
      </div>
    </div>
  );
}

function PaneHeader({
  icon: Icon,
  title,
  tone,
}: {
  icon: typeof FileText;
  title: string;
  tone: "muted" | "accent";
}) {
  return (
    <div className="flex shrink-0 items-center gap-2 border-b border-border bg-bg-panel px-4 py-2.5">
      <Icon className={`h-4 w-4 ${tone === "accent" ? "text-accent" : "text-text-muted"}`} strokeWidth={2} />
      <span className="text-xs font-semibold uppercase tracking-wider text-text-muted">{title}</span>
    </div>
  );
}

function SplitSkeleton() {
  return (
    <div className="space-y-3">
      <Skeleton className="h-40 w-full" />
      <Skeleton className="h-8 w-full" />
      <Skeleton className="h-8 w-full" />
    </div>
  );
}

function EmptyNote({ text }: { text: string }) {
  return <p className="text-sm text-text-faint">{text}</p>;
}
