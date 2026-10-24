/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies /api to the API on :8000 (strip prefix), like nginx does in Docker.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: false, rewrite: (p) => p.replace(/^\/api/, "") },
    },
  },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test-setup.ts"] },
});
