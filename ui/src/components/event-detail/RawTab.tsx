import { CheckCircle2, XCircle } from "lucide-react";

import { useEventRaw } from "../../api/hooks";
import Badge from "../Badge";
import Skeleton from "../Skeleton";
import { formatClockTime, formatCount } from "../../lib/format";

export default function RawTab({ eventUid }: { eventUid: string }) {
  const { data, isLoading } = useEventRaw(eventUid);

  if (isLoading) {
    return (
      <div className="space-y-4 p-4">
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-8 w-full" />
      </div>
    );
  }

  if (!data) {
    return <p className="p-4 text-sm text-text-faint">Raw event unavailable.</p>;
  }

  return (
    <div className="space-y-4 p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          {data.verified ? (
            <CheckCircle2 className="h-5 w-5 text-status-ok" strokeWidth={2} />
          ) : (
            <XCircle className="h-5 w-5 text-status-bad" strokeWidth={2} />
          )}
          <Badge tone={data.verified ? "ok" : "bad"}>
            {data.verified ? "verified — bytes match raw_hash" : "verification failed"}
          </Badge>
        </div>
      </div>

      <pre className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-bg-inset p-4 font-mono text-sm leading-relaxed text-text">
        {data.raw_text}
      </pre>

      <div className="grid grid-cols-2 gap-4 rounded-lg border border-border bg-bg-inset p-4 sm:grid-cols-3">
        <Field label="SHA-256" value={data.raw_hash} mono />
        <Field label="Length" value={`${formatCount(data.raw_len)} bytes`} />
        <Field label="Ingested" value={formatClockTime(data.ingest_time_ns)} />
        <Field label="Source ID" value={data.source_id} mono />
        <Field label="Transport" value={data.transport} />
        <Field label="Event UID" value={data.event_uid} mono />
      </div>
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
