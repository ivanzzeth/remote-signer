# e2e gap analysis (2026-05-20)

**Status:** all 12 items addressed. P0/P1/P2 land as unit + e2e tests
against the backend. P3 items reach into the extension/popup +
Playwright live-dapps spec. Per-item notes follow.

Triggered by a user-facing bug that no test caught: the file-based
template registry stored bundle templates with empty `type` and
without `config.rules_json`, so the preset → instantiate → sign path
silently sent every request to manual approval. The audit below lists
where coverage is missing and which gap each new test plugs.

Format per row: **[case]** — what the test asserts — which bug it
would have caught.

## P0 — would have caught the type="" bug ✅

1. **bundle-template + preset apply + sign auto-approve roundtrip** ✅ `TestBundleTemplate_RoundTrip`
   - Load a *shipped* bundle template (e.g. `evm/agent.yaml`), apply
     its preset, fire `personal_sign` matching its `sign_type_filter`,
     assert response `status=completed`, `rule_matched_id` equals the
     instantiated rule's ID, and the rule's `match_count` increments.
   - Would have caught: registry storing bundle as `type=""` →
     instantiated rule with empty type → rule engine logs "no
     evaluator… skipping" → unconditional manual approval.

2. **Template GET returns expected wire shape for bundle templates** ✅ covered by `TestBundleTemplate_RoundTrip` (asserts `type==template_bundle`, `config.rules_json` non-empty string)

3. **Rule CRUD: created rule preserves its type all the way to the engine** ✅ `TestRule_TypeFieldIsExposedInAPI` (create→list→get exposes type) + `TestRule_TypeRoundTripsToEngine` (sign auto-approves; match_count moves)

## P1 — adjacent paths the same root cause could damage ✅

4. **All shipped bundle templates load with the right shape** ✅ `TestFileTemplateSource_ShippedTemplatesNeverHaveEmptyType` + `TestFileTemplateSource_BundleWithRulesGetsRulesJSON` (walk `rules/templates/evm/`)

5. **Preset apply → list rules → match_count increments after sign** ✅ `TestPreset_Apply_MatchCountIncrements` (apply minimal preset → sign matching tx → assert `match_count` and `last_matched_at` move)

6. **Rule re-load (Upsert idempotence + shape repair)** ✅ `TestTemplateRepo_Upsert_HashFastPathSkipsWrite` + `TestTemplateRepo_Upsert_ShapeRepairForcesUpdate` (legacy bundle row with `type=""` repaired by re-Upsert even when content hash matches)

## P2 — depth/edge cases the audit surfaced ✅

7. **Empty/malformed bundle templates fail loudly** ✅ `TestFileTemplateSource_YAMLWithNoTypeAndNoRulesIsRejected` (validator rejects YAML with neither `type:` nor `rules:`)

8. **Rule engine "no evaluator for type" should fail-closed, not silent-skip** ✅ pushed validation up to storage boundary: `TestRuleRepo_Create_RejectsEmptyType` (rule_repo.Create rejects empty Type so the silent-skip case can't be persisted at all). Engine fail-open behavior left intact for forward-compat with future evaluator plugins; storage guard is the safety net.

9. **API surfaces: `rule list` / `rule get` MUST expose `type`** ✅ folded into `TestRule_TypeFieldIsExposedInAPI`

10. **Preset apply with template_bundle returns expanded sub-rule list** ✅ `TestPreset_Apply_BundleTemplate_ExpandsSubRules` (apply agent.preset → assert ≥2 newly-created rules, one whitelist + one blocklist matching evm/agent's sub-rules)

## P3 — extension-side coverage that would have shortened the debug loop ✅

11. **Live live-dapps Polymarket personal_sign asserts backend reaches `completed`** ✅ extended `extension/tests/live-dapps.spec.ts` (Polymarket case): after the existing recovery checks, the test builds a `RemoteSignerClient` from `serverInfo`, lists recent sign requests via the admin API, and asserts `status === "completed"` + `signature` is set on the most-recent `personal_sign` row. Gated behind `LIVE_DAPP_E2E=1` like the rest of the suite; spec parses under `playwright test --list`.

12. **Extension popup activity drawer shows "no rule matched" diagnostic** ✅ full stack:
    - **Storage:** `SignRequest.LastNoMatchReason` field (GORM AutoMigrate creates the column); `RequestRepository.UpdateLastNoMatchReason` writer.
    - **Service:** `sign.go` now calls `EvaluateWithResult`; persists `evalResult.NoMatchReason` on the request row before the manual-approval gate. Block path also handled via the result struct (in addition to the typed-error path).
    - **API:** `RequestDetailResponse.LastNoMatchReason` plumbed in `internal/api/handler/evm/request.go`; round-trip locked by `TestRequestHandler_GetSurfaces_LastNoMatchReason`.
    - **SDK:** `pkg/js-client/src/evm/requests.ts` exposes `last_no_match_reason` on `RequestStatusResponse`.
    - **Popup:** `extension/popup/popup.js::renderRequestDetail` renders `⚠ No whitelist rule matched: …` banner (with `data-testid="no-match-reason"`) when the field is set and `rule_matched_id` is empty.

## Notes on harness

- The e2e harness is `e2e/test_server.go` + the helpers in
  `e2e_helpers.go`. Templates and presets are mounted from
  `e2e/fixtures/` via `config.e2e.yaml`. To exercise *shipped*
  templates (P1 #4 / #5), copy or symlink them under
  `e2e/fixtures/rules/` (matching the registry's expected layout).
- The agent preset references `evm/agent` template id — fixture must
  expose both for the preset to resolve.
