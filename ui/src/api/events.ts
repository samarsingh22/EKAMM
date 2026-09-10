import { api, toQueryString } from "./client";
import type {
  EventDetail,
  EventLineage,
  EventListParams,
  EventListResponse,
  EventRaw,
  EventsStatsSummary,
  EventsTimeseries,
} from "./types";

/** `/api/v1/events` — see `ulpf/api/routes/events.py`. */
export const eventsApi = {
  list: (params: EventListParams = {}): Promise<EventListResponse> =>
    api.get(`/events/${toQueryString(params)}`),

  get: (eventUid: string): Promise<EventDetail> => api.get(`/events/${encodeURIComponent(eventUid)}`),

  raw: (eventUid: string): Promise<EventRaw> => api.get(`/events/${encodeURIComponent(eventUid)}/raw`),

  lineage: (eventUid: string): Promise<EventLineage> =>
    api.get(`/events/${encodeURIComponent(eventUid)}/lineage`),

  statsSummary: (): Promise<EventsStatsSummary> => api.get("/events/stats/summary"),

  statsTimeseries: (interval = "1m", window = "1h"): Promise<EventsTimeseries> =>
    api.get(`/events/stats/timeseries${toQueryString({ interval, window })}`),
};
