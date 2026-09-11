// ⑬ web/(嵌进守护进程二进制的 React SPA)的 lint 配置 —— **类型感知**。
//
// ⛔ 2026-09-11 之前这里**一个 lint 配置都没有**,`package.json` 里也没有
// `lint` 脚本。也就是说 16,668 行 TSX 完全没有 lint 在看 —— 而 tsc 只看类型,
// 它不会告诉你一个 promise 没被 await。这个 UI 负责**发起签名请求**,
// 一个被丢掉的 promise 在这里的表现是「点了按钮,界面显示成功,而请求没发出去」。
//
// 规则集与 pkg/js-client/eslint.config.mjs **保持一致**,理由见那个文件的顶注:
// 两边都是同一个 daemon 的客户端代码,判据不该有两套。
//
// ⚠️ 作用域是 `src/`(含 src/lib/*.test.ts —— 它们在 tsconfig.json 的 include 里)。
// `tests/e2e/` 是 Playwright 的地盘,**不在 tsconfig 里**,给它开类型感知要另一份
// tsconfig —— 单独的决定,不在这次改动里。
//
// ⭐ 没有装 eslint-plugin-react-hooks / react-refresh。那是一个**决定**而不是
// 疏漏:它们抓的是另一类缺陷(hook 依赖数组),值得单独评估,而把它们塞进
// 这次改动会让基线里混进几十条与「promise / any / ts-ignore」无关的发现。
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "tests/**",
      "playwright-report/**",
      "test-results/**",
      "*.config.js",
      "*.config.mjs",
      "*.config.ts",
    ],
  },
  js.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
      globals: { ...globals.browser },
    },
    rules: {
      // ---------- 与 js-client 同一套「抓缺陷」的规则,全部 error ----------
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/only-throw-error": "error",
      "@typescript-eslint/ban-ts-comment": [
        "error",
        {
          "ts-ignore": true,
          "ts-expect-error": "allow-with-description",
          "ts-nocheck": true,
          "ts-check": false,
          minimumDescriptionLength: 10,
        },
      ],
      "@typescript-eslint/no-explicit-any": "error",

      // ---------- 降噪,理由同 js-client ----------
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/restrict-template-expressions": "off",
    },
  },
);
