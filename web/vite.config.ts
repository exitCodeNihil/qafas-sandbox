import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/**
 * Dev: Vite serves the console with HMR on :5173 and proxies API traffic to the
 * Go control plane on :7800.
 * Prod: `npm run build` emits dist/, which controlplane/web/embed.go bakes into the binary.
 *
 * Override the backend with SBX_DEV_BACKEND when running elsewhere.
 */
const backend = process.env.SBX_DEV_BACKEND ?? "http://localhost:7800";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "../controlplane/web/dist", emptyOutDir: true },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: backend, ws: true },
      "/healthz": { target: backend },
    },
  },
});
