/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Light SOC theme. One accent (cyan) carries every interactive/
        // "live" signal; everything else stays a near-monochrome grayscale so
        // the accent (and semantic status colors) are the only things that
        // pull the eye. Accent and status shades are dark enough to read as
        // text on white.
        bg: {
          DEFAULT: "#f8fafc", // page background
          panel: "#ffffff", // cards / sidebar / topbar
          elevated: "#eef2f7", // hovered rows, popovers
          inset: "#f1f5f9", // wells (code blocks, raw log preview)
        },
        border: {
          DEFAULT: "#e2e8f0",
          subtle: "#edf1f6",
        },
        text: {
          DEFAULT: "#0f172a", // primary, high-contrast
          muted: "#475569", // secondary
          faint: "#64748b", // tertiary / disabled
        },
        accent: {
          DEFAULT: "#0e7490",
          dim: "#155e75",
          bg: "rgba(14, 116, 144, 0.1)",
        },
        // status colors (errors/warnings/ok) are semantic, not "the accent" -
        // kept intentionally separate per the single-accent brief.
        status: {
          ok: "#047857",
          warn: "#b45309",
          bad: "#dc2626",
        },
      },
      keyframes: {
        "toast-in": {
          "0%": { opacity: "0", transform: "translate(-50%, 0.5rem)" },
          "100%": { opacity: "1", transform: "translate(-50%, 0)" },
        },
        "flash-accent": {
          "0%, 100%": { backgroundColor: "transparent" },
          "35%": { backgroundColor: "rgba(14, 116, 144, 0.25)" },
        },
      },
      animation: {
        "toast-in": "toast-in 0.25s ease-out",
        "flash-accent": "flash-accent 900ms ease-out",
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "Helvetica Neue",
          "Arial",
          "sans-serif",
        ],
        // Log/raw-evidence content only - system monospace stack, no
        // network font fetch (keeps the UI usable in an air-gapped deploy).
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "Liberation Mono",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
