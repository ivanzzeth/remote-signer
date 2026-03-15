# TUI: HD Wallets 并入 Signers 设计

## 目标

- 把 **HD Wallets** 从顶层导航移入 **Signers** 页面，作为 Signers 下的子页面。
- 当前 **Signers** 页面（签名地址列表：keystore + HD 派生地址）也作为 Signers 下的一个子页面，并起一个合适的名字。
- 顶层 Tab 从 8 个减到 7 个，结构更清晰：所有「签名人/密钥」相关入口统一在 Signers 下。

## 命名

| 位置 | 名称 | 说明 |
|------|------|------|
| 顶层 Tab | **Signers** | 保持不变，表示「签名人/密钥」入口 |
| 子页 0 | **List** | 当前 Signers 页面：所有签名地址列表（keystore + HD 派生），解锁/加锁、创建 keystore 等 |
| 子页 1 | **HD Wallets** | 当前 HD Wallets 页面：HD 钱包管理（创建/导入、派生地址、解锁 HD 钱包） |

子页 0 命名为 **List**，表示「签名人列表」，与 **HD Wallets**（HD 钱包管理）区分开且不重复顶层名。若希望更直白，可改为 **Signers**（与顶层同名，表示「列表」子页）或 **All Signers**。

## 当前 vs 拟议

| 当前 | 拟议 |
|------|------|
| 8 个顶层 Tab：… [5] Signers [6] Metrics [7] HD Wallets [8] Security | 7 个顶层 Tab：… [5] **Signers** [6] Metrics [7] Security |
| 数字键 5=Signers，6=Metrics，7=HD Wallets，8=Security | 数字键 5=Signers，6=Metrics，7=Security |
| Tab/Shift+Tab 在 8 个 Tab 间循环 | Tab/Shift+Tab 在 7 个 Tab 间循环；在 **Signers** 时多一层子 Tab：**List** \| **HD Wallets** |

## 界面草图

### 1) 顶层不在 Signers 时

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ Remote Signer TUI                                                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [1] Dashboard  [2] Requests  [3] ACLs  [4] Audit  [5] Signers  [6] Metrics  [7] Security │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2) 顶层在 Signers，子页为「List」（当前 Signers 列表）

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ Remote Signer TUI                                                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [1] Dashboard  [2] Requests  [3] ACLs  [4] Audit  [5] Signers  [6] Metrics  [7] Security │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│   List   │   HD Wallets     ← 仅当顶层为 Signers 时显示；当前高亮 List                    │
└─────────────────────────────────────────────────────────────────────────────────────────┘
│ Address              Type        Locked    Unlocked at    ...                            │
│ 0xf39Fd...266        keystore    No        -              ...                            │
│ 0x7099...9C8         hd_wallet    Yes       -              ...                            │
│ ...                                                                                      │
```

### 3) 顶层在 Signers，子页为「HD Wallets」

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ Remote Signer TUI                                                                        │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ [1] Dashboard  [2] Requests  [3] ACLs  [4] Audit  [5] Signers  [6] Metrics  [7] Security │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│   List   │ ▶ HD Wallets ◀   ← 高亮 HD Wallets                                            │
└─────────────────────────────────────────────────────────────────────────────────────────┘
│ Primary Address       Derived   ...                                                      │
│ 0x1234...abcd         ../../.   ...                                                      │
│ ...                                                                                      │
```

### 4) 从 List 进入 Signer 详情 / 从 HD Wallets 进入 HD Wallet 详情

- 行为与现在一致：仍在 Signers 顶层下，Esc/Back 回到对应子页列表。

## 交互约定

| 操作 | 行为 |
|------|------|
| 数字键 1–7 | 切换到对应顶层 Tab。按 **5** 时进入 Signers 且子页为 **List**（签名人列表）。 |
| Tab / Shift+Tab | 仅在**顶层** Tab 间循环（7 个 Tab）。 |
| **← / → 方向键** | 当顶层为 Signers 时：在 **List** / **HD Wallets** 两个子页间切换。 |
| Esc / Back | 若在 Signer 详情 / HD Wallet 详情则返回对应列表；否则按现有逻辑。 |

## 实现要点

1. **状态**
   - 保留现有 `ViewSigners` / `ViewHDWallets` / `ViewSignerDetail` / `ViewHDWalletDetail`。
   - 顶层 `activeTab`：0–6 对应 7 个 Tab（当前 4=Signers, 5=Metrics, 6=HD Wallets, 7=Security → 改为 4=Signers, 5=Metrics, 6=Security）。
   - 新增 `signersSubTab int`：0=List（当前 Signers 列表）, 1=HD Wallets。仅当 `currentView` 为 ViewSigners 或 ViewHDWallets 时有效。

2. **Header 渲染**
   - 第一行：7 个 Tab，`[1] Dashboard` … `[7] Security`。
   - 当 `activeTab == 4`（Signers）时，第二行渲染子 Tab：`List | HD Wallets`，根据 `signersSubTab` 高亮当前项。

3. **← / → 方向键（Signers 子页）**
   - 仅当 `currentView` 为 ViewSigners 或 ViewHDWallets 时处理。
   - **→**：List → HD Wallets（再按 → 循环回 List）。
   - **←**：HD Wallets → List（再按 ← 循环回 HD Wallets）。
   - 切换后根据 signersSubTab 设 currentView 并 refresh 对应 view。

4. **数字键 5**
   - 设 `activeTab = 4`，`currentView = ViewSigners`，`signersSubTab = 0`，并 refresh Signers 列表。

5. **Tab/Shift+Tab**
   - 总 Tab 数改为 7；(activeTab + 1) % 7 与 (activeTab + 6) % 7。
   - 当切换到 activeTab == 4 时，设 `signersSubTab = 0`。

6. **删除**
   - 顶层 Tab 列表和 `tabToView` 中移除 HD Wallets（原 index 6）；Metrics 变为 5，Security 变为 6。
   - 移除数字键 7（HD Wallets）、8（Security）中的 8；改为 6=Metrics，7=Security（即 Number6、Number7）。

7. **keyMap**
   - Number6 对应 Metrics（activeTab 5），Number7 对应 Security（activeTab 6）。删除原 Number8（若存在则改为 7 个 Tab 后的对应关系）。

8. **isTopLevelView**
   - ViewSigners、ViewHDWallets 仍视为顶层 Tab 下的视图（按 Tab 可离开 Signers 顶层）。

## 小结

- 顶层只保留 7 个 Tab，HD Wallets 收进 Signers 下的子 Tab。
- 在 Signers 区域用 **← / →** 在 **List**（签名人列表）/ **HD Wallets** 间切换；Tab/Shift+Tab 只循环顶层 7 个 Tab；数字键 1–7 对应顶层。
- 签名人列表、HD 钱包列表及 Signer 详情、HD Wallet 详情行为保持不变，仅入口和切换路径改变。
