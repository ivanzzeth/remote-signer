import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Output directly into the Go embed directory so `go build ./...` after a
// `npm run build` picks up the freshly compiled bundle without an extra copy
// step. The placeholder index.html committed there is overwritten cleanly.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: path.resolve(__dirname, "../internal/web/dist"),
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      // Forward API + system probes to the daemon so dev mode behaves like
      // production. Run the daemon on 8548 (the default), then
      // `remote-signer settings set web dev_proxy=http://localhost:5173`
      // to make the daemon proxy "/" to Vite, OR open localhost:5173
      // directly with this proxy handling /api/*.
      "/api": "http://127.0.0.1:8548",
      "/health": "http://127.0.0.1:8548",
      "/metrics": "http://127.0.0.1:8548",
    },
  },
});
