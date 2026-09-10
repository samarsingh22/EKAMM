import { api } from "./client";
import type {
  DisableSourceResponse,
  ReloadStatus,
  SourceDetail,
  SourceListItem,
  SourceTestResponse,
  ValidateResponse,
  WriteSourceResponse,
} from "./types";

/** `/api/v1/sources` — see `ulpf/api/routes/sources.py`. */
export const sourcesApi = {
  list: (): Promise<SourceListItem[]> => api.get("/sources/"),

  get: (name: string): Promise<SourceDetail> => api.get(`/sources/${encodeURIComponent(name)}`),

  /** Body is raw YAML text. */
  validate: (yamlText: string): Promise<ValidateResponse> => api.postText("/sources/validate", yamlText),

  test: (yamlText: string, sampleLines: string[]): Promise<SourceTestResponse> =>
    api.post("/sources/test", { yaml: yamlText, sample_lines: sampleLines }),

  /** Body is raw YAML text; validates, backs up the previous version, writes, hot-reloads. */
  write: (name: string, yamlText: string): Promise<WriteSourceResponse> =>
    api.putText(`/sources/${encodeURIComponent(name)}`, yamlText),

  /** Disables (moves to `.disabled/`) — never deletes. */
  disable: (name: string): Promise<DisableSourceResponse> =>
    api.delete(`/sources/${encodeURIComponent(name)}`),

  reloadStatus: (): Promise<ReloadStatus> => api.get("/sources/reload-status"),
};
