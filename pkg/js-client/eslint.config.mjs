// ⑬ remote-signer-client 的 lint 配置 —— **类型感知**。
//
// ---------- 为什么换掉 .eslintrc.json ----------
//
// ⛔ 上一版有两个问题,而两个都不是「风格」问题:
//
//   1. **没有任何东西在跑它。** `package.json` 里有 `"lint": "eslint src --ext .ts"`,
//      仓库里有 .eslintrc.json,而 `make check` / scripts/lib/layers.sh /
//      .github/workflows/* 里**一次都没出现过 eslint**。实测:2026-09-11 第一次
//      真的跑它,当场 **3 个 error**(no-unused-vars)—— 也就是说这条门禁红着,
//      而没有人看得见。⚠️ 本仓库第三次踩到同一个形状(.githooks 没装、
//      blackbox 层重放缓存、这一条),所以第一个问题永远是「有东西在跑它吗?」。
//
//   2. **`plugin:@typescript-eslint/recommended` 不看类型。** 它只有语法规则,
//      于是 `no-floating-promises` / `no-misused-promises` / `only-throw-error`
//      **根本没被启用** —— 而这是一个**给签名请求签名**的客户端:一个没有 await
//      的 promise 意味着「调用方以为签完了」,一条静默的成功路径。
//      判据和 Go 侧门禁 ⑫ 完全一样。
//
// ---------- 类型感知不是免费的 ----------
//
// `projectService: true` 会让 typescript-eslint 真的建一棵 TS program。代价实测
// 见 scripts/check-js-lint.sh 顶部。⛔ 它也意味着**被 lint 的文件必须在 tsconfig
// 的 include 里** —— 否则 typescript-eslint 直接报错(而不是静默降级成语法规则,
// 那种降级正是上一版的病)。
//
// ⚠️ 作用域是 `src/`,与上一版一致:那是被 npm publish 出去的那部分。
// tests/ 不在 tsconfig.json 的 include 里,给它开类型感知要另一份 tsconfig ——
// 那是一个单独的决定,不在这次改动里。
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import security from "eslint-plugin-security";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "docs/**",
      "examples/**",
      "scripts/**",
      "tests/**",
      "coverage/**",
      "test-results/**",
      "*.config.js",
      "*.config.mjs",
    ],
  },
  js.configs.recommended,
  // ⭐ TypeChecked,不是普通的 recommended。差别就是上面说的那三条规则。
  tseslint.configs.recommendedTypeChecked,
  security.configs.recommended,
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      parserOptions: {
        // projectService 让 typescript-eslint 自己找 tsconfig。
        // ⛔ 别换回 `project: true` 之外的写法而不验证:配错了它**不会**降级成
        // 语法模式,它会直接红 —— 那是好事,见 check-js-lint.sh 的 ④。
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // ---------- 这四条是这次改动的**理由**,全部是 error ----------
      //
      // 它们只有在类型感知下才存在。它们抓的不是风格,是「调用方以为做完了而
      // 实际没做」这一类缺陷 —— 在一个签名客户端里,那等于一条静默的成功路径。
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/only-throw-error": "error",
      // `@ts-ignore` 把一个**真实的类型错误**永久静音,而且不留下任何理由。
      // `@ts-expect-error` 至少在错误消失时会自己报废;要求带说明。
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
      // ⚠️ 上一版是 "warn" —— 在门禁里 warn **等于没有**(eslint 的退出码只看
      // error)。改成 error 之后今天有 45 处,由 scripts/lib/arch-baseline/js-lint.txt
      // 的计数棘轮兜着,不许涨。
      "@typescript-eslint/no-explicit-any": "error",

      // ---------- 下面是**降噪**,每条都写清为什么 ----------
      //
      // ⛔ 降噪不是放松判据:被降的每一条要么在类型感知下必然大面积误报,
      // 要么它管的是风格。真正抓缺陷的那几条在上面,全是 error。

      // 这个客户端要处理来自 HTTP 的任意 JSON。`unknown` 经过 JSON.parse 后
      // 一定是 any,这四条会在每一处解析上各响一次,而它们指向的是同一个
      // 「边界处要收窄类型」的问题 —— 那是 no-explicit-any 已经在管的事。
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      // 模板串里放 number/boolean 是本仓库到处都在做的事,不是缺陷。
      "@typescript-eslint/restrict-template-expressions": "off",
      // eslint-plugin-security 的这条对 `obj[key]` 一律报警,而 TS 的索引类型
      // 已经在管它。实测 3 处全部是误报(常量 key)。
      "security/detect-object-injection": "off",
    },
  },
);
