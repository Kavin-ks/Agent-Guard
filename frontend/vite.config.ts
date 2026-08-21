/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard talks to the backend via a same-origin "/api" prefix. In dev,
// this proxy forwards "/api/*" to the FastAPI backend and injects the X-API-Key
// header SERVER-SIDE (from the AGENTGUARD_API_KEY env of the dev server process).
// The browser bundle therefore never contains the API key. In production, a
// reverse proxy (nginx / BFF) performs the same injection — see README.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: process.env.VITE_BACKEND_URL || "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq) => {
            const key = process.env.AGENTGUARD_API_KEY;
            if (key) proxyReq.setHeader("X-API-Key", key);
          });
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test/setup.ts",
    css: false,
  },
});
