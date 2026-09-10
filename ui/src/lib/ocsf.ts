/**
 * Small display lookups mirroring `ulpf/normalize/ocsf/base.py`'s constants
 * (`CLASS_NAMES`, `SEVERITY_ID`) — kept minimal (just what the dashboard
 * renders), not a full port of the schema.
 */

export const CLASS_NAMES: Record<number, string> = {
  2004: "Detection Finding",
  4001: "Network Activity",
  4002: "HTTP Activity",
  4003: "DNS Activity",
};

export function classLabel(classUid: number | null | undefined): string {
  if (classUid === null || classUid === undefined) return "Unknown";
  return CLASS_NAMES[classUid] ?? `Class ${classUid}`;
}

const SEVERITY_NAMES: Record<number, string> = {
  0: "Unknown",
  1: "Informational",
  2: "Low",
  3: "Medium",
  4: "High",
  5: "Critical",
  6: "Fatal",
  99: "Other",
};

export function severityLabel(severityId: number | null | undefined): string {
  if (severityId === null || severityId === undefined) return "—";
  return SEVERITY_NAMES[severityId] ?? `Severity ${severityId}`;
}

export type Tone = "ok" | "warn" | "bad" | "muted";

/** Informational/Low -> ok, Medium -> warn, High/Critical/Fatal -> bad. */
export function severityTone(severityId: number | null | undefined): Tone {
  if (severityId === null || severityId === undefined) return "muted";
  if (severityId >= 4) return "bad";
  if (severityId === 3) return "warn";
  return "ok";
}

export function actionLabel(actionId: number | null | undefined): string {
  if (actionId === 1) return "Allowed";
  if (actionId === 2) return "Denied";
  if (actionId === null || actionId === undefined) return "—";
  return `Action ${actionId}`;
}

export function actionTone(actionId: number | null | undefined): Tone {
  if (actionId === 1) return "ok";
  if (actionId === 2) return "bad";
  return "muted";
}
