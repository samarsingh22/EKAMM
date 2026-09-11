/**
 * Chart series colors. The UI's single "brand" accent (cyan) still anchors
 * everything chrome/interactive, but a stacked/multi-series chart genuinely
 * needs several distinguishable hues — this is a small qualitative palette
 * built from and around that accent, not a departure from it.
 */
const PALETTE = [
  "#0891b2", // accent (cyan)
  "#059669", // emerald
  "#6366f1", // indigo
  "#d97706", // amber
  "#db2777", // pink
  "#0284c7", // sky
  "#7c3aed", // violet
  "#ea580c", // orange
  "#0d9488", // teal
  "#dc2626", // red
  "#65a30d", // lime
];

/** A stable color for `key` (e.g. a `source_type`) — same key always maps to the same color. */
export function colorForKey(key: string): string {
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
  }
  return PALETTE[hash % PALETTE.length];
}
