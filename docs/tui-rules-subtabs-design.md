# TUI: Rules 收纳 Templates / Presets 设计

## 目标

- 把 **Templates** 和 **Presets** 从顶层导航移入 **Rules** 页面，作为 Rules 下的子页面。
- 顶层 Tab 从 11 个减到 9 个，数字键 1–9 可一一对应，避免“按键太多无法跳转”。

## 当前 vs 拟议

| 当前 | 拟议 |
|------|------|
| 11 个顶层 Tab：Dashboard, Requests, Rules, Audit, Signers, Metrics, HD Wallets, Security, API Keys, **Templates**, **Presets** | 9 个顶层 Tab：Dashboard, Requests, **Rules**, Audit, Signers, Metrics, HD Wallets, Security, API Keys |
| 数字键 1–9 对应前 9 个，0 对应 Templates；Presets 无数字键 | 数字键 1–9 对应全部 9 个顶层 Tab |
| Tab/Shift+Tab 在 11 个 Tab 间循环 | Tab/Shift+Tab 在 9 个 Tab 间循环；在 **Rules** 时多一层子 Tab：Rules → Templates → Presets |

## 界面草图

### 1) 顶层不在 Rules 时（例如 Dashboard）

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ Remote Signer TUI                                                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [1] Dashboard  [2] Requests  [3] Rules  [4] Audit  [5] Signers  [6] Metrics  [7] HD…  [8] Security  [9] API Keys │
└─────────────────────────────────────────────────────────────────────────────────────────┘
│                                                                                          │
│  (当前页内容，例如 Dashboard / Requests / …)                                               │
│                                                                                          │
```

### 2) 顶层在 Rules 且子页为「Rules」时（规则列表）

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ Remote Signer TUI                                                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [1] Dashboard  [2] Requests  [3] Rules  [4] Audit  [5] Signers  [6] Metrics  [7] HD…  [8] Security  [9] API Keys │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│   Rules   │   Templates   │   Presets     ← 仅当顶层为 Rules 时显示；当前高亮 Rules      │
└─────────────────────────────────────────────────────────────────────────────────────────┘
│ ID                                   Name              Type        Mode    Enabled  ...  │
│ abc-123                              Allow treasury    evm_addr…   allow   ✓             │
│ def-456                              ERC20 limit       evm_js      allow   ✓             │
│ ...                                                                                      │
│                                                                                          │
│ ↑/↓: navigate | Enter: view details | t: toggle | d: delete | ... | n/p: next/prev | r: refresh │
```

### 3) 顶层在 Rules 且子页为「Templates」时

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ Remote Signer TUI                                                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [1] Dashboard  [2] Requests  [3] Rules  [4] Audit  [5] Signers  [6] Metrics  [7] HD…  [8] Security  [9] API Keys │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│   Rules   │ ▶ Templates ◀  │   Presets     ← 高亮 Templates                              │
└─────────────────────────────────────────────────────────────────────────────────────────┘
│ ID / Name                    Variables / Paths                                            │
│ ERC20 Template               chain_id, token_address, max_transfer_amount, ...            │
│ Polymarket Safe Template     chain_id, ctf_exchange_address, ...                         │
│ ...                                                                                       │
│ ↑/↓: navigate | n/p: next/prev page | r: refresh                                          │
```

### 4) 顶层在 Rules 且子页为「Presets」时

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ Remote Signer TUI                                                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [1] Dashboard  [2] Requests  [3] Rules  [4] Audit  [5] Signers  [6] Metrics  [7] HD…  [8] Security  [9] API Keys │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│   Rules   │   Templates   │ ▶ Presets ◀    ← 高亮 Presets                                │
└─────────────────────────────────────────────────────────────────────────────────────────┘
│ Preset ID / Name                                                                          │
│ e2e_minimal.preset.yaml                                                                   │
│ erc20.preset.js.yaml                                                                      │
│ ...                                                                                       │
│ ↑/↓: navigate | Enter: open detail & apply | r: refresh                                   │
```

### 5) 从 Presets 进入 Preset 详情

- 仍在「Rules」顶层 Tab 下，子页为 Presets；内容区变为 Preset 详情（vars、Apply 等）。
- Esc/Back 回到 Presets 列表（子页不变）。

### 6) 从 Rules 列表进入 Rule 详情

- 行为与现在一致：Esc/Back 回到 Rules 列表（子页仍是 Rules）。

## 交互约定

| 操作 | 行为 |
|------|------|
| 数字键 1–9 | 切换到对应顶层 Tab。按 **3** 时进入 Rules 且子页为 **Rules**（规则列表）。 |
| Tab / Shift+Tab | 仅在**顶层**Tab 间循环（Dashboard ↔ … ↔ API Keys），不进入子页循环。 |
| **← / → 方向键** | 当顶层为 Rules 时：在 Rules / Templates / Presets 三个子页间切换（Rules 页面未绑定左右键，可安全使用）。 |
| Esc / Back | 若在 Rule 详情 / Preset 详情则返回对应列表；否则按现有逻辑。 |
| 子页切换 | 仅通过 **← / →** 在 Rules / Templates / Presets 间切换。 |

## 实现要点（供编码参考）

1. **状态**
   - 保留现有 `ViewRules` / `ViewTemplates` / `ViewPresets`（及 Rule 详情、Preset 详情）。
   - 顶层 `activeTab`：0–8 对应 9 个 Tab（去掉原 9、10 的 Templates、Presets）。
   - 新增 `rulesSubTab int`：0=Rules, 1=Templates, 2=Presets。仅当 `currentView` 为 ViewRules/ViewTemplates/ViewPresets 时有效。

2. **Header 渲染**
   - 第一行：9 个 Tab，`[1] Dashboard` … `[9] API Keys`。
   - 当 `activeTab == 2`（Rules）时，第二行渲染子 Tab：`Rules | Templates | Presets`，根据 `rulesSubTab` 高亮当前项。

3. **← / → 方向键（Rules 子页）**
   - 仅当 `currentView` 为 ViewRules / ViewTemplates / ViewPresets 时处理。
   - **→**：Rules → Templates → Presets（到 Presets 后再按 → 无效果或循环回 Rules，建议循环回 Rules）。
   - **←**：Presets → Templates → Rules（到 Rules 后再按 ← 无效果或循环到 Presets，建议循环到 Presets）。
   - 切换后根据 rulesSubTab 设 currentView 并 refresh 对应 view。

4. **数字键 3**
   - 设 `activeTab = 2`，`currentView = ViewRules`，`rulesSubTab = 0`，并 refresh Rules 列表。

5. **删除**
   - 顶层 Tab 列表和 `tabToView` 中移除 Templates、Presets。
   - 移除 `keys.Number0` 对 Templates 的绑定。

6. **keyMap**
   - 新增 `Left` / `Right` binding（`left` / `right`），用于 Rules 子 Tab；FullHelp 可加入一行提示。

7. **子 Tab 样式**
   - 复用或仿造 `TabStyle` / `ActiveTabStyle`，子 Tab 行可略小一号或略淡，以区分层级。

## 小结

- 导航栏只保留 9 个 Tab，Templates 和 Presets 收进 Rules 下的子 Tab。
- 在 Rules 区域用 **← / →** 在 Rules / Templates / Presets 间切换；Tab/Shift+Tab 只循环顶层 9 个 Tab；数字键 1–9 稳定对应顶层。
- 规则列表、模板列表、Preset 列表及各自详情行为保持不变，仅入口和切换路径改变。
