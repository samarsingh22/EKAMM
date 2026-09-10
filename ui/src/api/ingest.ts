import { api } from "./client";
import type {
  IngestReplayProgress,
  IngestResult,
  ListenerStatus,
  ReplayStartResponse,
  SampleRequest,
} from "./types";

/** `/api/v1/ingest` — see `ulpf/api/routes/ingest.py`. */
export const ingestApi = {
  sample: (payload: SampleRequest): Promise<IngestResult> => api.post("/ingest/sample", payload),

  startReplay: (file: string, rateEps: number): Promise<ReplayStartResponse> =>
    api.post("/ingest/replay", { file, rate_eps: rateEps }),

  replayProgress: (taskId: string): Promise<IngestReplayProgress> =>
    api.get(`/ingest/replay/${encodeURIComponent(taskId)}`),

  stopReplay: (taskId: string): Promise<IngestReplayProgress> =>
    api.delete(`/ingest/replay/${encodeURIComponent(taskId)}`),

  listeners: (): Promise<ListenerStatus[]> => api.get("/ingest/listeners"),
};
