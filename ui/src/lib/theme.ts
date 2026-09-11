/**
 * Hex values mirroring `tailwind.config.js`'s theme — for contexts (recharts'
 * inline SVG styling) that can't reach Tailwind's design tokens directly.
 * Keep these in sync with `tailwind.config.js` by hand.
 */
export const THEME = {
  bgPanel: "#ffffff",
  bgElevated: "#eef2f7",
  border: "#e2e8f0",
  textMuted: "#475569",
  textFaint: "#64748b",
  accent: "#0e7490",
} as const;
