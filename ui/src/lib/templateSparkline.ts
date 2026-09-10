import type { DriftEntry } from "../api/types";

/**
 * Ascending window widths sampled from `GET /templates/drift` to reconstruct
 * a per-template frequency history: there is no dedicated time-series
 * endpoint for templates, but `drift`'s `observed_in_window` is a genuine,
 * real *cumulative* count ("events in the last W"), so subtracting
 * consecutive windows yields real, non-overlapping historical buckets —
 * not a fabricated shape.
 */
export const SPARKLINE_WINDOWS = ["15m", "1h", "4h", "12h", "24h"] as const;

const WINDOW_SECONDS: Record<(typeof SPARKLINE_WINDOWS)[number], number> = {
  "15m": 900,
  "1h": 3600,
  "4h": 14400,
  "12h": 43200,
  "24h": 86400,
};

export function templateKey(t: { template_id: string; source_id: string }): string {
  return `${t.source_id}::${t.template_id}`;
}

/**
 * `windowSeries[i]` is the `drift` response for `SPARKLINE_WINDOWS[i]` (or
 * `undefined` if that window hasn't loaded yet). Returns
 * `template_key -> events/minute per bucket, oldest first`.
 */
export function buildTemplateSparklines(
  windowSeries: (DriftEntry[] | undefined)[],
): Map<string, number[]> {
  const keys = new Set<string>();
  for (const entries of windowSeries) {
    for (const entry of entries ?? []) keys.add(templateKey(entry));
  }

  const result = new Map<string, number[]>();
  for (const key of keys) {
    const cumulative = windowSeries.map(
      (entries) => entries?.find((e) => templateKey(e) === key)?.observed_in_window ?? 0,
    );

    const ratesNewestFirst: number[] = [];
    let prevCount = 0;
    let prevSeconds = 0;
    for (let i = 0; i < SPARKLINE_WINDOWS.length; i++) {
      const seconds = WINDOW_SECONDS[SPARKLINE_WINDOWS[i]];
      const bucketCount = Math.max(0, cumulative[i] - prevCount);
      const bucketSeconds = Math.max(1, seconds - prevSeconds);
      ratesNewestFirst.push((bucketCount / bucketSeconds) * 60);
      prevCount = cumulative[i];
      prevSeconds = seconds;
    }
    result.set(key, ratesNewestFirst.reverse()); // oldest-first, matching left-to-right reading
  }
  return result;
}
