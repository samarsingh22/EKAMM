/**
 * React Query hooks over `src/api/*.ts`. Every "live" hook here polls at
 * {@link LIVE_REFETCH_MS} (2s) — cheap enough for a single-operator SOC
 * dashboard, and short enough that the top bar's EPS/connection indicator
 * reads as genuinely live.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef } from "react";

import { dlqApi } from "./dlq";
import { eventsApi } from "./events";
import { ingestApi } from "./ingest";
import { integrityApi } from "./integrity";
import { sourcesApi } from "./sources";
import { suggestApi } from "./suggest";
import { templatesApi } from "./templates";
import type {
  DlqListParams,
  EventListParams,
  GenerateSourceRequest,
  ReplayRequest,
} from "./types";

export const LIVE_REFETCH_MS = 2_000;

/** Query key roots, so a future mutation (e.g. `PUT /sources/{name}`) can invalidate precisely. */
export const queryKeys = {
  events: {
    list: (params: EventListParams) => ["events", "list", params] as const,
    detail: (uid: string) => ["events", "detail", uid] as const,
    raw: (uid: string) => ["events", "raw", uid] as const,
    lineage: (uid: string) => ["events", "lineage", uid] as const,
    statsSummary: () => ["events", "stats-summary"] as const,
    timeseries: (interval: string, window: string) => ["events", "timeseries", interval, window] as const,
  },
  sources: {
    list: () => ["sources", "list"] as const,
    detail: (name: string) => ["sources", "detail", name] as const,
    reloadStatus: () => ["sources", "reload-status"] as const,
  },
  templates: {
    list: (sourceId?: string) => ["templates", "list", sourceId ?? null] as const,
    unknown: () => ["templates", "unknown"] as const,
    detail: (templateId: string, sourceId?: string) =>
      ["templates", "detail", templateId, sourceId ?? null] as const,
    drift: (window: string, sourceId?: string) => ["templates", "drift", window, sourceId ?? null] as const,
  },
  integrity: {
    status: () => ["integrity", "status"] as const,
    ledger: () => ["integrity", "ledger"] as const,
    proof: (eventUid: string) => ["integrity", "proof", eventUid] as const,
  },
  dlq: {
    list: (params: DlqListParams) => ["dlq", "list", params] as const,
    stats: () => ["dlq", "stats"] as const,
  },
  ingest: {
    listeners: () => ["ingest", "listeners"] as const,
    replayProgress: (taskId: string) => ["ingest", "replay", taskId] as const,
  },
};

// ---------------------------------------------------------------------------
// events.py

export function useEventsList(params: EventListParams = {}, live = false) {
  return useQuery({
    queryKey: queryKeys.events.list(params),
    queryFn: () => eventsApi.list(params),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

export function useEventDetail(eventUid: string | undefined) {
  return useQuery({
    queryKey: queryKeys.events.detail(eventUid ?? ""),
    queryFn: () => eventsApi.get(eventUid as string),
    enabled: Boolean(eventUid),
  });
}

export function useEventRaw(eventUid: string | undefined) {
  return useQuery({
    queryKey: queryKeys.events.raw(eventUid ?? ""),
    queryFn: () => eventsApi.raw(eventUid as string),
    enabled: Boolean(eventUid),
  });
}

export function useEventLineage(eventUid: string | undefined) {
  return useQuery({
    queryKey: queryKeys.events.lineage(eventUid ?? ""),
    queryFn: () => eventsApi.lineage(eventUid as string),
    enabled: Boolean(eventUid),
  });
}

export function useEventsStatsSummary(live = true, enabled = true) {
  return useQuery({
    queryKey: queryKeys.events.statsSummary(),
    queryFn: () => eventsApi.statsSummary(),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
    enabled,
  });
}

export function useEventsTimeseries(interval = "1m", window = "1h", live = true) {
  return useQuery({
    queryKey: queryKeys.events.timeseries(interval, window),
    queryFn: () => eventsApi.statsTimeseries(interval, window),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

/**
 * The top bar's live figures, all off one 2s `stats/summary` poll (never two
 * concurrent pollers for the same data): `parse_success_rate` straight from
 * the response, plus `eps` derived client-side from consecutive samples
 * (`total_events` delta / elapsed seconds, `null` until a second sample
 * lands), plus that poll's own success/failure as the connection signal.
 */
export function useLiveStats(): {
  eps: number | null;
  parseSuccessRate: number | null;
  isError: boolean;
  isFetching: boolean;
  isSuccess: boolean;
} {
  const { data, isError, isFetching, isSuccess } = useEventsStatsSummary(true);
  const previous = useRef<{ total: number; atMs: number } | null>(null);
  const eps = useRef<number | null>(null);

  if (data) {
    const now = Date.now();
    const prev = previous.current;
    if (prev) {
      const elapsedS = (now - prev.atMs) / 1000;
      if (elapsedS > 0) {
        eps.current = Math.max(0, (data.total_events - prev.total) / elapsedS);
      }
    }
    previous.current = { total: data.total_events, atMs: now };
  }

  return {
    eps: eps.current,
    parseSuccessRate: data?.parse_success_rate ?? null,
    isError,
    isFetching,
    isSuccess,
  };
}

// ---------------------------------------------------------------------------
// sources.py

export function useSourcesList(live = false) {
  return useQuery({
    queryKey: queryKeys.sources.list(),
    queryFn: () => sourcesApi.list(),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

export function useSourceDetail(name: string | undefined) {
  return useQuery({
    queryKey: queryKeys.sources.detail(name ?? ""),
    queryFn: () => sourcesApi.get(name as string),
    enabled: Boolean(name),
  });
}

export function useSourcesReloadStatus(live = false) {
  return useQuery({
    queryKey: queryKeys.sources.reloadStatus(),
    queryFn: () => sourcesApi.reloadStatus(),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

/** `POST /sources/validate` — the editor calls `.mutate(yamlText)` on every debounced keystroke. */
export function useValidateSourceYaml() {
  return useMutation({
    mutationFn: (yamlText: string) => sourcesApi.validate(yamlText),
  });
}

/** `POST /sources/test` — the editor's live preview, re-run on every debounced yaml/sample change. */
export function useTestSource() {
  return useMutation({
    mutationFn: ({ yamlText, sampleLines }: { yamlText: string; sampleLines: string[] }) =>
      sourcesApi.test(yamlText, sampleLines),
  });
}

/** `PUT /sources/{name}` — "Save & Activate". Invalidates the source list/reload-status on success. */
export function useWriteSource() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ name, yamlText }: { name: string; yamlText: string }) => sourcesApi.write(name, yamlText),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["sources"] });
    },
  });
}

/** `POST /suggest/parser` — "Generate from samples". */
export function useGenerateSourceSuggestion() {
  return useMutation({
    mutationFn: (payload: GenerateSourceRequest) => suggestApi.parser(payload),
  });
}

// ---------------------------------------------------------------------------
// templates.py

export function useTemplatesList(sourceId?: string, live = false) {
  return useQuery({
    queryKey: queryKeys.templates.list(sourceId),
    queryFn: () => templatesApi.list(sourceId),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

export function useTemplatesUnknown(live = false) {
  return useQuery({
    queryKey: queryKeys.templates.unknown(),
    queryFn: () => templatesApi.unknown(),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

export function useTemplateDetail(templateId: string | undefined, sourceId?: string) {
  return useQuery({
    queryKey: queryKeys.templates.detail(templateId ?? "", sourceId),
    queryFn: () => templatesApi.get(templateId as string, sourceId),
    enabled: Boolean(templateId),
  });
}

export function useTemplatesDrift(window = "1h", sourceId?: string, live = true) {
  return useQuery({
    queryKey: queryKeys.templates.drift(window, sourceId),
    queryFn: () => templatesApi.drift(window, sourceId),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

/**
 * "Generate Parser": fetches this template's stored samples (for the
 * editor's sample-lines pane) and its suggested definition in parallel,
 * closing the "unknown log -> working parser" loop in one click.
 */
export function useGenerateParserFromTemplate() {
  return useMutation({
    mutationFn: async ({ templateId, sourceId }: { templateId: string; sourceId: string }) => {
      const [detail, suggestion] = await Promise.all([
        templatesApi.get(templateId, sourceId),
        templatesApi.suggest(templateId, sourceId),
      ]);
      return { yaml: suggestion.yaml, sampleLines: detail.sample_lines, score: suggestion.score };
    },
  });
}

// ---------------------------------------------------------------------------
// integrity.py

export function useIntegrityStatus(live = true) {
  return useQuery({
    queryKey: queryKeys.integrity.status(),
    queryFn: () => integrityApi.status(),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

export function useIntegrityLedger(live = true) {
  return useQuery({
    queryKey: queryKeys.integrity.ledger(),
    queryFn: () => integrityApi.ledger(),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

/** `POST /integrity/verify/chain` — the "Verify Now" button's first phase. */
export function useVerifyChain() {
  return useMutation({ mutationFn: () => integrityApi.verifyChain() });
}

/** `POST /integrity/verify/events` — the "Verify Now" button's second phase. */
export function useVerifyEvents() {
  return useMutation({ mutationFn: (date?: string) => integrityApi.verifyEvents(date) });
}

/**
 * `GET /integrity/proof/{event_uid}` — the full Merkle-proof verification,
 * fetched on demand (the lineage tab's "Verify this event" button calls
 * `refetch()`), not automatically, since it is the more expensive re-hash +
 * re-verify path rather than the cheap `lineage` summary.
 */
export function useEventProof(eventUid: string | undefined) {
  return useQuery({
    queryKey: queryKeys.integrity.proof(eventUid ?? ""),
    queryFn: () => integrityApi.proof(eventUid as string),
    enabled: false,
    retry: false,
  });
}

// ---------------------------------------------------------------------------
// dlq.py

export function useDlqList(params: DlqListParams = {}, live = false) {
  return useQuery({
    queryKey: queryKeys.dlq.list(params),
    queryFn: () => dlqApi.list(params),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

export function useDlqStats(live = true) {
  return useQuery({
    queryKey: queryKeys.dlq.stats(),
    queryFn: () => dlqApi.stats(),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

/** `POST /dlq/replay` — the per-reason-group "Replay" button. */
export function useDlqReplay() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ReplayRequest) => dlqApi.replay(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["dlq"] });
    },
  });
}

/**
 * "Suggest parser for these": pulls every raw preview for one dead-letter
 * reason and feeds them to `POST /suggest/parser`, closing the loop the same
 * way the Templates page does.
 */
export function useSuggestParserFromDlqReason() {
  return useMutation({
    mutationFn: async (reason: string) => {
      const list = await dlqApi.list({ reason, page_size: 50 });
      const sampleLines = list.items.map((item) => item.raw_preview).filter(Boolean);
      if (sampleLines.length < 3) {
        throw new Error("need at least 3 sample lines to suggest a parser");
      }
      const suggestion = await suggestApi.parser({
        source_id: reason || "dlq-source",
        sample_lines: sampleLines,
      });
      return { yaml: suggestion.yaml, sampleLines };
    },
  });
}

// ---------------------------------------------------------------------------
// ingest.py

export function useIngestListeners(live = true) {
  return useQuery({
    queryKey: queryKeys.ingest.listeners(),
    queryFn: () => ingestApi.listeners(),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}

export function useReplayProgress(taskId: string | undefined, live = true) {
  return useQuery({
    queryKey: queryKeys.ingest.replayProgress(taskId ?? ""),
    queryFn: () => ingestApi.replayProgress(taskId as string),
    enabled: Boolean(taskId),
    refetchInterval: live ? LIVE_REFETCH_MS : false,
  });
}
