/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Near-black SOC theme. One accent (cyan) carries every interactive/
        // "live" signal; everything else stays a near-monochrome grayscale so
        // the accent (and semantic status colors) are the only things that
        // pull the eye.
        bg: {
          DEFAULT: "#08090c", // page background
          panel: "#101218", // cards / sidebar / topbar
          elevated: "#181b23", // hovered rows, popovers
          inset: "#05060a", // wells (code blocks, raw log preview)
        },
        border: {
          DEFAULT: "#22242e",
          subtle: "#181a22",
        },
        text: {
          DEFAULT: "#e6e7eb", // primary, high-contrast
          muted: "#9498a6", // secondary
          faint: "#5b5f6e", // tertiary / disabled
        },
        accent: {
          DEFAULT: "#22d3ee",
          dim: "#0e7490",
          bg: "rgba(34, 211, 238, 0.1)",
        },
        // status colors (errors/warnings/ok) are semantic, not "the accent" -
        // kept intentionally separate per the single-accent brief.
        status: {
          ok: "#34d399",
          warn: "#fbbf24",
          bad: "#f87171",
        },
      },
      keyframes: {
        "toast-in": {
          "0%": { opacity: "0", transform: "translate(-50%, 0.5rem)" },
          "100%": { opacity: "1", transform: "translate(-50%, 0)" },
        },
        "flash-accent": {
          "0%, 100%": { backgroundColor: "transparent" },
          "35%": { backgroundColor: "rgba(34, 211, 238, 0.35)" },
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
