import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// Dev server only: `/` opens the landing page (ui/landing/index.html) and its
// "Open the console" link goes to `/console/`, the dashboard's Overview. Every
// other path still falls through to the dashboard. Builds (and so `ulpf serve`)
// are unaffected. ui/landing needs its own `npm install` (for three.js).
function landingPage(): Plugin {
  return {
    name: "ulpf-landing-page",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use((incoming, _res, next) => {
        // no @types/node in this project, so Connect's request type lacks `url`
        const req = incoming as unknown as { url?: string };
        const path = req.url?.split("?")[0];
        if (path === "/") req.url = "/landing/index.html";
        else if (path === "/ekam-mark.svg") req.url = "/landing/public/ekam-mark.svg";
        next();
      });
    },
  };
}

// ULPF dashboard dev server. `/api` proxies to the management API
// (`ulpf serve`, default port 8080) so the UI can call relative paths
// (`/api/v1/...`) in both dev and the built/served-behind-nginx production
// container, with no environment-specific base URL to configure.
export default defineConfig({
  plugins: [react(), landingPage()],
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
