/**
 * Chart series colors. The UI's single "brand" accent (cyan) still anchors
 * everything chrome/interactive, but a stacked/multi-series chart genuinely
 * needs several distinguishable hues — this is a small qualitative palette
 * built from and around that accent, not a departure from it.
 */
const PALETTE = [
  "#22d3ee", // accent (cyan)
  "#34d399", // emerald
  "#818cf8", // indigo
  "#fbbf24", // amber
  "#f472b6", // pink
  "#38bdf8", // sky
  "#a78bfa", // violet
  "#fb923c", // orange
  "#2dd4bf", // teal
  "#f87171", // red
  "#a3e635", // lime
];

/** A stable color for `key` (e.g. a `source_type`) — same key always maps to the same color. */
export function colorForKey(key: string): string {
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
  }
  return PALETTE[hash % PALETTE.length];
}
