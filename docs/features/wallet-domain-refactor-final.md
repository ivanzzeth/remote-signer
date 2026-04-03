# Wallet Domain Refactor (Final)

## Status

- Owner decision: **approved**
- Compatibility: **none**
- Data policy: **reset to clean state**

## Non-Negotiable Rules

1. `signer` and `wallet` are different domain concepts.
2. `wallet` is an explicit organizational container (formerly wallet), created by API.
3. `wallet` must not have `keystore` or `hd_wallet` as wallet types.
4. `hd_wallet` is only a signer source pattern (primary + derived signers), not a wallet domain object.
5. No backward compatibility layer. No dual semantics. No frontend merge hacks.

## Final Domain Model

### Signer

- Represents a concrete signing identity.
- Includes:
  - keystore signer
  - hd-derived signer (including hd primary signer)
  - other future signer kinds

### Wallet

- Represents a logical grouping container for signers.
- Created explicitly by user/admin.
- Has owner and membership list.
- Exists independently from signer storage implementation.

### Membership

- `wallet` contains many `signers`.
- A signer can be member of multiple wallets (subject to policy).

## Rename Plan (Hard Rename, No Compatibility)

### DB Tables

- Rename `wallet_wallets` -> `wallets`
- Rename `wallet_members` -> `wallet_members`

### API Surface

- Replace `/api/v1/wallets*` with `/api/v1/wallets*` wallet-management endpoints.
- Keep signer APIs under `/api/v1/evm/signers*` for signer lifecycle and signer operations.
- Remove wallet listing semantics based on `signers?group_by_wallet=true`.

### Code Naming

- `WalletCollection` -> `Wallet`
- `CollectionMember` -> `WalletMember`
- `CollectionRepository` -> `WalletRepository`
- `WalletService` -> `WalletService`
- `WalletAPI` (client) -> `WalletAPI`

## Data Strategy

- No migration scripts for old wallet schema.
- Drop old data and recreate clean schema.
- Local keystore/hd key material files remain untouched.
- Re-import / recreate runtime metadata in clean DB as needed.

## Backend Architecture Changes

### 1) Wallet Management (new canonical source)

- Wallet list endpoint must query `wallets` table only.
- Wallet detail and membership endpoints must query `wallets` + `wallet_members`.
- Pagination, filtering, and access control apply at wallet domain level.

### 2) Signer Management (independent)

- Signer listing endpoint returns signers only.
- Signer API no longer doubles as wallet catalog.
- `group_by_wallet` behavior is removed (or endpoint path removed) to prevent concept leakage.

### 3) Access Control

- Wallet ownership and grants are evaluated against wallet IDs.
- Signer ownership and grants remain signer-address based.
- Cross-check rules must be explicit and fail closed.

## TUI Changes

### Wallets Page

- Shows only explicit wallets from wallet API.
- No rows for `keystore` or `hd_wallet`.
- Create/delete wallet operations apply to wallet entity.

### Wallet Detail

- Shows signer members of selected wallet.
- Add/remove member works on signer IDs (addresses).
- No special branch treating hd wallet as wallet type.

### Signers Page

- Continues to manage signers (create/unlock/lock/delete/tag/filter).
- HD behavior remains signer-side only.

## CLI/SDK Changes

- CLI:
  - `evm wallet *` commands become real wallet domain commands (CRUD + members).
  - signer commands stay under `evm signer *`.
- SDK:
  - Separate interfaces for signer domain and wallet domain.
  - Remove signer API methods that pretend to be wallet catalog (`ListWallets` based on grouped signers).

## Removed Behavior

- Any frontend-side merge of signer wallets + wallets.
- Any API response where wallet rows are synthesized from signer grouping.
- Any wallet type enum containing `keystore` or `hd_wallet`.

## Test Requirements (Must Pass Before Release)

1. Wallet CRUD
   - create/get/list/delete wallet
2. Wallet membership
   - add/remove/list signer members
3. Access control
   - owner/grantee/admin behavior for wallet operations
4. Signer independence
   - signer list unaffected by wallet list semantics
5. TUI behavior
   - wallets page shows only explicit wallets
   - signers page manages only signers
6. Clean-state bootstrap
   - empty DB startup
   - schema recreation succeeds

## Rollout Sequence

1. Freeze current mixed wallet logic.
2. Implement DB schema rename (`wallets`, `wallet_members`) in clean baseline migration set.
3. Refactor storage + service + handlers to wallet domain naming.
4. Refactor SDK + CLI + TUI to new wallet APIs.
5. Remove grouped-signer wallet codepaths.
6. Run full test matrix (unit + e2e + manual TUI/CLI checks).
7. Deploy clean-state environment.

## Acceptance Criteria

- Wallet list contains only explicitly created wallets.
- No `wallet_type=keystore` or `wallet_type=hd_wallet` anywhere.
- Signers and wallets are fully separated in API, UI, and code.
- No compatibility shims, no fallback glue, no dual model.

