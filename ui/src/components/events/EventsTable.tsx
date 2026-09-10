import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

import type { EventRow } from "../../api/types";
import Badge from "../Badge";
import Skeleton from "../Skeleton";
import { formatClockTime } from "../../lib/format";
import { actionLabel, actionTone, classLabel, severityLabel, severityTone } from "../../lib/ocsf";

const GRID_COLS = "grid-cols-[96px_150px_120px_1fr_100px_120px]";
const ROW_HEIGHT = 40;
const VIEWPORT_HEIGHT = 560;

interface EventsTableProps {
  items: EventRow[];
  loading: boolean;
  selectedUid?: string | null;
  onRowClick: (eventUid: string) => void;
}

function eventDestination(row: EventRow): string {
  const src = row.src_ip ? `${row.src_ip}${row.src_port ? `:${row.src_port}` : ""}` : "—";
  const dst = row.dst_ip ? `${row.dst_ip}${row.dst_port ? `:${row.dst_port}` : ""}` : "—";
  return `${src} → ${dst}`;
}

/** A results table whose body is virtualized (`@tanstack/react-virtual`) — only the rows scrolled into view are ever mounted. */
export default function EventsTable({ items, loading, selectedUid, onRowClick }: EventsTableProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  });

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-bg-panel">
      <div className={`grid ${GRID_COLS} gap-2 border-b border-border px-4 py-2 text-xs font-medium uppercase tracking-wide text-text-faint`}>
        <div>Time</div>
        <div>Source</div>
        <div>Class</div>
        <div>Src → Dst</div>
        <div>Action</div>
        <div>Severity</div>
      </div>

      {loading ? (
        <div className="divide-y divide-border-subtle">
          {Array.from({ length: 14 }).map((_, i) => (
            <div key={i} className="flex items-center px-4" style={{ height: ROW_HEIGHT }}>
              <Skeleton className="h-4 w-full" />
            </div>
          ))}
        </div>
      ) : items.length === 0 ? (
        <div className="px-4 py-10 text-center text-sm text-text-faint">No events match these filters.</div>
      ) : (
        <div ref={scrollRef} className="overflow-y-auto" style={{ height: VIEWPORT_HEIGHT }}>
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((virtualRow) => {
              const row = items[virtualRow.index];
              return (
                <div
                  key={row.event_uid}
                  onClick={() => onRowClick(row.event_uid)}
                  className={`absolute left-0 top-0 grid w-full ${GRID_COLS} cursor-pointer items-center gap-2 border-b border-border-subtle px-4 text-sm transition-colors hover:bg-bg-elevated ${
                    selectedUid === row.event_uid ? "bg-accent-bg" : ""
                  }`}
                  style={{ height: virtualRow.size, transform: `translateY(${virtualRow.start}px)` }}
                >
                  <div className="truncate font-mono text-text-muted">{formatClockTime(row.time ?? null)}</div>
                  <div className="truncate text-text">{row.source_type ?? "—"}</div>
                  <div className="truncate text-text-muted">
                    {row.class_uid !== undefined ? classLabel(row.class_uid) : "—"}
                  </div>
                  <div className="truncate font-mono text-text-muted">{eventDestination(row)}</div>
                  <div className="truncate">
                    <Badge tone={actionTone(row.action_id ?? null)}>
                      {row.action ?? actionLabel(row.action_id ?? null)}
                    </Badge>
                  </div>
                  <div className="truncate">
                    <Badge tone={severityTone(row.severity_id ?? null)}>
                      {row.severity ?? severityLabel(row.severity_id ?? null)}
                    </Badge>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
