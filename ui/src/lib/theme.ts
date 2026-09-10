/**
 * Hex values mirroring `tailwind.config.js`'s theme — for contexts (recharts'
 * inline SVG styling) that can't reach Tailwind's design tokens directly.
 * Keep these in sync with `tailwind.config.js` by hand.
 */
export const THEME = {
  bgPanel: "#101218",
  bgElevated: "#181b23",
  border: "#22242e",
  textMuted: "#9498a6",
  textFaint: "#5b5f6e",
  accent: "#22d3ee",
} as const;
