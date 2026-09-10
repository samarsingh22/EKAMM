/** Shared number/time formatting — used by the top bar and every dashboard page. */

export function formatEps(eps: number | null | undefined): string {
  if (eps === null || eps === undefined) return "—";
  return eps < 10 ? eps.toFixed(1) : Math.round(eps).toLocaleString();
}

export function formatPercent(rate: number | null | undefined, digits = 1): string {
  if (rate === null || rate === undefined) return "—";
  return `${(rate * 100).toFixed(digits)}%`;
}

export function formatCount(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return n.toLocaleString();
}

/** Epoch nanoseconds -> a `Date`, or `null` for a missing/invalid value. */
export function nsToDate(ns: number | null | undefined): Date | null {
  if (ns === null || ns === undefined || Number.isNaN(ns)) return null;
  return new Date(ns / 1_000_000);
}

export function formatClockTime(ns: number | null | undefined): string {
  const date = nsToDate(ns);
  return date ? date.toLocaleTimeString(undefined, { hour12: false }) : "—";
}

/** Date + time, for timestamps that may be well in the past (e.g. a template's first_seen). */
export function formatDateTime(ns: number | null | undefined): string {
  const date = nsToDate(ns);
  if (!date) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

/** e.g. "3h ago", "5m ago" — for a compact relative-time cell. */
export function formatRelativeTime(ns: number | null | undefined): string {
  const date = nsToDate(ns);
  if (!date) return "—";
  const seconds = (Date.now() - date.getTime()) / 1000;
  if (seconds < 60) return "just now";
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)}m ago`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)}h ago`;
  const days = hours / 24;
  return `${Math.round(days)}d ago`;
}
