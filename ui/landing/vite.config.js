import { defineConfig } from "vite";

// Standalone landing page (index.html, copied verbatim from the EKAM frontend).
// Independent of the dashboard in ui/: its own package.json, node_modules and
// dist/. Port 5174 so it can run alongside the dashboard dev server on 5173.
export default defineConfig({
  // An inline (empty) PostCSS config stops Vite from walking up to
  // ui/postcss.config.js and running the dashboard's Tailwind over this page.
  css: { postcss: {} },
  server: { port: 5174 },
  preview: { port: 5174 },
  build: { outDir: "dist", emptyOutDir: true },
});
