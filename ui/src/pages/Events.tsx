import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { useEventsList, useSourcesList } from "../api/hooks";
import type { EventListParams } from "../api/types";
import EventDetail from "../components/EventDetail";
import FilterBar, { EMPTY_FILTERS, type EventFilterState, type TimePreset } from "../components/events/FilterBar";
import EventsTable from "../components/events/EventsTable";
import Pagination from "../components/events/Pagination";
import { useDebouncedValue } from "../lib/useDebouncedValue";

const PRESET_MS: Record<Exclude<TimePreset, "all">, number> = {
  "15m": 15 * 60 * 1000,
  "1h": 60 * 60 * 1000,
  "6h": 6 * 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
};

function presetToTimeFromNs(preset: TimePreset): number | undefined {
  if (preset === "all") return undefined;
  return (Date.now() - PRESET_MS[preset]) * 1_000_000;
}

export default function Events() {
  const navigate = useNavigate();
  const { eventUid } = useParams<{ eventUid?: string }>();

  const [filters, setFilters] = useState<EventFilterState>(EMPTY_FILTERS);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  const debouncedQ = useDebouncedValue(filters.q, 400);
  const debouncedSrcIp = useDebouncedValue(filters.srcIp, 400);
  const debouncedDstIp = useDebouncedValue(filters.dstIp, 400);

  const sourcesQuery = useSourcesList();
  const sourceOptions = useMemo(
    () => (sourcesQuery.data ?? []).map((s) => s.name).sort(),
    [sourcesQuery.data],
  );

  const queryParams: EventListParams = useMemo(
    () => ({
      page,
      page_size: pageSize,
      source_type: filters.sourceType || undefined,
      class_uid: filters.classUid ? Number(filters.classUid) : undefined,
      action_id: filters.actionId ? Number(filters.actionId) : undefined,
      src_ip: debouncedSrcIp || undefined,
      dst_ip: debouncedDstIp || undefined,
      time_from: presetToTimeFromNs(filters.timePreset),
      q: debouncedQ || undefined,
    }),
    [page, pageSize, filters.sourceType, filters.classUid, filters.actionId, filters.timePreset, debouncedSrcIp, debouncedDstIp, debouncedQ],
  );

  // filters changed (anything but page/pageSize itself) -> back to page 1
  useEffect(() => {
    setPage(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.sourceType, filters.classUid, filters.actionId, filters.timePreset, debouncedSrcIp, debouncedDstIp, debouncedQ]);

  const eventsQuery = useEventsList(queryParams, true);

  const openEvent = (uid: string) => navigate(`/events/${encodeURIComponent(uid)}`);
  const closeEvent = () => navigate("/events");

  return (
    <div className="space-y-4">
      <FilterBar
        value={filters}
        onChange={(patch) => setFilters((prev) => ({ ...prev, ...patch }))}
        sourceOptions={sourceOptions}
      />

      <EventsTable
        items={eventsQuery.data?.items ?? []}
        loading={eventsQuery.isLoading}
        selectedUid={eventUid}
        onRowClick={openEvent}
      />

      <Pagination
        page={page}
        pageSize={pageSize}
        total={eventsQuery.data?.total ?? 0}
        onPageChange={setPage}
        onPageSizeChange={(size) => {
          setPageSize(size);
          setPage(1);
        }}
      />

      <EventDetail eventUid={eventUid} onClose={closeEvent} />
    </div>
  );
}
