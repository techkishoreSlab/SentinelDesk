/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { type Plugin, defineConfig } from "vite";

const backend = process.env["SENTINEL_BACKEND_URL"] ?? "http://127.0.0.1:8000";

// Cookies, the backend Origin allow-list and the Entra redirect URI are all bound to
// http://localhost:5173, so a page loaded from 127.0.0.1 can never sign in.
const canonicalHost: Plugin = {
  name: "sentineldesk-canonical-host",
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (req.headers.host === "127.0.0.1:5173") {
        res.statusCode = 307;
        res.setHeader("Location", `http://localhost:5173${req.url ?? "/"}`);
        res.end();
        return;
      }
      next();
    });
  },
};

// The dev server proxies API calls so the browser talks to a single origin
// (required for SameSite cookies and CSRF protection in later phases).
export default defineConfig({
  plugins: [react(), canonicalHost],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target: backend, changeOrigin: false },
      "/health": { target: backend, changeOrigin: false },
    },
  },
  build: { sourcemap: false },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./tests/setup.ts"],
    include: ["tests/**/*.test.{ts,tsx}"],
  },
});
