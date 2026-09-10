import { api, toQueryString } from "./client";
import type { DriftEntry, TemplateDetail, TemplateOut, TemplateSuggestResponse } from "./types";

/** `/api/v1/templates` — see `ulpf/api/routes/templates.py`. */
export const templatesApi = {
  list: (sourceId?: string): Promise<TemplateOut[]> =>
    api.get(`/templates/${toQueryString({ source_id: sourceId })}`),

  /** Same catalog as `list()`, unfiltered — the "what to onboard next" worklist. */
  unknown: (): Promise<TemplateOut[]> => api.get("/templates/unknown"),

  get: (templateId: string, sourceId?: string): Promise<TemplateDetail> =>
    api.get(`/templates/${encodeURIComponent(templateId)}${toQueryString({ source_id: sourceId })}`),

  suggest: (templateId: string, sourceId?: string): Promise<TemplateSuggestResponse> =>
    api.post(
      `/templates/${encodeURIComponent(templateId)}/suggest${toQueryString({ source_id: sourceId })}`,
    ),

  drift: (window = "1h", sourceId?: string): Promise<DriftEntry[]> =>
    api.get(`/templates/drift${toQueryString({ window, source_id: sourceId })}`),
};
