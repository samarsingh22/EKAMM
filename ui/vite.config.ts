import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// ULPF dashboard dev server. `/api` proxies to the management API
// (`ulpf serve`, default port 8080) so the UI can call relative paths
// (`/api/v1/...`) in both dev and the built/served-behind-nginx production
// container, with no environment-specific base URL to configure.
export default defineConfig({
  plugins: [react()],
  // `make ui-build` -> ui/dist, which ulpf/api/app.py serves at / when present.
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
