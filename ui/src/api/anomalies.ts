import { api, toQueryString } from "./client";
import type {
  AnomalyListParams,
  AnomalyRow,
  AnomalyTimeline,
  ModelInfo,
  TemplateDriftSignal,
  TrainModelRequest,
  TrainModelResult,
} from "./types";

/** `/api/v1/anomalies` — see `ulpf/api/routes/anomalies.py`. */
export const anomaliesApi = {
  list: (params: AnomalyListParams = {}): Promise<AnomalyRow[]> =>
    api.get(`/anomalies/${toQueryString(params)}`),

  /** The trained detector's provenance card (`{ trained: false }` before any training run). */
  model: (): Promise<ModelInfo> => api.get("/anomalies/model"),

  timeline: (window = "1h", bucket = "1m"): Promise<AnomalyTimeline> =>
    api.get(`/anomalies/timeline${toQueryString({ window, bucket })}`),

  drift: (
    windowMinutes = 5,
    zThreshold = 3,
    sourceId?: string,
  ): Promise<TemplateDriftSignal[]> =>
    api.get(
      `/anomalies/drift${toQueryString({
        window_minutes: windowMinutes,
        z_threshold: zThreshold,
        source_id: sourceId,
      })}`,
    ),

  train: (body: TrainModelRequest): Promise<TrainModelResult> => api.post("/anomalies/train", body),
};
