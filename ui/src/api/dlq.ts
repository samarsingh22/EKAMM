import { api, toQueryString } from "./client";
import type { DlqListParams, DlqListResponse, DlqStats, ReplayRequest, ReplayReport } from "./types";

/** `/api/v1/dlq` — see `ulpf/api/routes/dlq.py`. */
export const dlqApi = {
  list: (params: DlqListParams = {}): Promise<DlqListResponse> => api.get(`/dlq/${toQueryString(params)}`),

  stats: (): Promise<DlqStats> => api.get("/dlq/stats"),

  replay: (payload: ReplayRequest = {}): Promise<ReplayReport> => api.post("/dlq/replay", payload),
};
