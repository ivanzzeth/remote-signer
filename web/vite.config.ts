// `vitest/config` re-exports Vite's `defineConfig` widened with the `test`
// key — importing it from "vite" instead is what left `test` unconfigurable
// (and the Vitest/Playwright collision below unfixable) in the first place.
import { defineConfig, configDefaults } from "vitest/config";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Output directly into the Go embed directory so `go build ./...` after a
// `npm run build` picks up the freshly compiled bundle without an extra copy
// step. The placeholder index.html committed there is overwritten cleanly.
export default defineConfig({
  plugins: [react()],
  // ⛔ tests/e2e/ 是 Playwright 的地盘,不能让 Vitest 也去收。
  //
  // Vitest 的默认 include(`**/*.{test,spec}.?(c|m)[jt]s?(x)`)会把
  // tests/e2e/*.spec.ts 一并收进来,每个文件在 collect 阶段就炸:
  // "Playwright Test did not expect test() to be called here"。
  // 实测 `npm test` = 42 个文件红、5 个绿 —— 而那 5 个绿的单测本身
  // 一直是好的,红全部来自这个收集范围。⚠️ 表现是「npm test 一直红」,
  // 于是没人再看它,单测层就此静默失守。
  //
  // 判据:*把这一行删掉,`npm test` 会不会红?* 会 —— 42 个文件。
  test: {
    exclude: [...configDefaults.exclude, "tests/e2e/**"],
  },
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
