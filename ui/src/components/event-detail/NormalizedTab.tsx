import type { ReactNode } from "react";

import { useEventDetail } from "../../api/hooks";
import Badge from "../Badge";
import JsonTree from "../JsonTree";
import Skeleton from "../Skeleton";
import { formatClockTime } from "../../lib/format";
import { actionTone, classLabel, severityTone } from "../../lib/ocsf";
import { getNumber, getString } from "../../lib/objectPath";

export default function NormalizedTab({ eventUid }: { eventUid: string }) {
  const { data, isLoading } = useEventDetail(eventUid);

  if (isLoading) {
    return (
      <div className="space-y-4 p-4">
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-96 w-full" />
      </div>
    );
  }

  if (!data) {
    return <p className="p-4 text-sm text-text-faint">Normalized record unavailable.</p>;
  }

  const classUid = getNumber(data, ["class_uid"]);
  const severityId = getNumber(data, ["severity_id"]);
  const actionId = getNumber(data, ["action_id"]);
  const time = getNumber(data, ["time"]);
  const srcIp = getString(data, ["src_endpoint", "ip"]);
  const srcPort = getNumber(data, ["src_endpoint", "port"]);
  const dstIp = getString(data, ["dst_endpoint", "ip"]);
  const dstPort = getNumber(data, ["dst_endpoint", "port"]);
  const sourceType = getString(data, ["source_type"]);
  const action = getString(data, ["action"]);
  const severity = getString(data, ["severity"]);

  return (
    <div className="space-y-4 p-4">
      {/* promoted summary */}
      <div className="grid grid-cols-2 gap-3 rounded-lg border border-border bg-bg-inset p-4 sm:grid-cols-3">
        <SummaryField label="Class" value={classUid !== undefined ? classLabel(classUid) : "—"} />
        <SummaryField label="Source" value={sourceType ?? "—"} />
        <SummaryField label="Time" value={formatClockTime(time ?? null)} />
        <SummaryField
          label="Src → Dst"
          value={
            srcIp || dstIp
              ? `${srcIp ?? "—"}${srcPort ? `:${srcPort}` : ""} → ${dstIp ?? "—"}${dstPort ? `:${dstPort}` : ""}`
              : "—"
          }
          mono
        />
        <SummaryField
          label="Action"
          value={<Badge tone={actionTone(actionId ?? null)}>{action ?? "—"}</Badge>}
        />
        <SummaryField
          label="Severity"
          value={<Badge tone={severityTone(severityId ?? null)}>{severity ?? "—"}</Badge>}
        />
      </div>

      {/* full record */}
      <div className="rounded-lg border border-border bg-bg-inset p-4 font-mono text-xs leading-relaxed">
        <JsonTree data={data} defaultExpandDepth={1} />
      </div>
    </div>
  );
}

function SummaryField({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-[11px] uppercase tracking-wide text-text-faint">{label}</div>
      <div className={`truncate text-sm text-text ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}
