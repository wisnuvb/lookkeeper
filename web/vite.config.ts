import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: {
    outDir: "dist",
    sourcemap: false,
    // The UI is embedded in the Go binary, so keep the entry small and let routes load on demand.
    chunkSizeWarningLimit: 600,
  },
  server: { host: "127.0.0.1", port: 5173, strictPort: true },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
