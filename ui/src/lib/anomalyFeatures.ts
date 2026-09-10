/**
 * Plain-English rendering of the anomaly detector's feature columns
 * (see `ulpf/ml/features.py`). An analyst on shift should read
 * "distinct destination ports: 847 vs typical 3", never `win_distinct_dst_ports`.
 */

const LABELS: Record<string, string> = {
  bytes_in: "bytes received",
  bytes_out: "bytes sent",
  bytes_ratio: "sent/received byte ratio",
  packets: "packet count",
  duration: "connection duration",
  dst_port: "destination port",
  is_well_known_port: "well-known destination port",
  is_ephemeral_port: "ephemeral destination port",
  protocol_num: "IP protocol number",
  action_id: "action code (allow/deny)",
  severity_id: "severity code",
  hour_of_day: "hour of day",
  day_of_week: "day of week",
  is_private_src: "private source address",
  is_private_dst: "private destination address",
  direction_id: "traffic direction code",
  win_connection_count: "connections in 5-min window",
  win_distinct_dst_ips: "distinct destination IPs (5-min window)",
  win_distinct_dst_ports: "distinct destination ports (5-min window)",
  win_deny_ratio: "denied fraction (5-min window)",
  win_total_bytes_out: "bytes sent (5-min window)",
  win_mean_bytes_per_conn: "mean bytes per connection (5-min window)",
  win_distinct_protocols: "distinct protocols (5-min window)",
};

/** Human label for a feature column; falls back to de-snake-casing an unknown name. */
export function featureLabel(feature: string): string {
  return LABELS[feature] ?? feature.replace(/^win_/, "").replace(/_/g, " ");
}

/** Compact value formatting — fractions keep 2dp, large counts abbreviate. */
export function featureValue(feature: string, value: number): string {
  if (!Number.isFinite(value)) return "—";
  if (feature.includes("ratio")) return value.toFixed(2);
  const abs = Math.abs(value);
  if (abs >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (abs >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

/** e.g. "distinct destination ports (5-min window): 847 vs typical 3". */
export function explainInEnglish(e: {
  feature: string;
  value: number;
  training_median: number;
}): string {
  return `${featureLabel(e.feature)}: ${featureValue(e.feature, e.value)} vs typical ${featureValue(
    e.feature,
    e.training_median,
  )}`;
}
