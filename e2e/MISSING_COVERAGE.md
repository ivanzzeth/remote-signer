# e2e gap analysis (2026-05-20)

Triggered by a user-facing bug that no test caught: the file-based
template registry stored bundle templates with empty `type` and
without `config.rules_json`, so the preset → instantiate → sign path
silently sent every request to manual approval. The audit below lists
where coverage is missing and which gap each new test plugs.

Format per row: **[case]** — what the test asserts — which bug it
would have caught.

## P0 — would have caught the type="" bug

1. **bundle-template + preset apply + sign auto-approve roundtrip**
   - Load a *shipped* bundle template (e.g. `evm/agent.yaml`), apply
     its preset, fire `personal_sign` matching its `sign_type_filter`,
     assert response `status=completed`, `rule_matched_id` equals the
     instantiated rule's ID, and the rule's `match_count` increments.
   - Would have caught: registry storing bundle as `type=""` →
     instantiated rule with empty type → rule engine logs "no
     evaluator… skipping" → unconditional manual approval.

2. **Template GET returns expected wire shape for bundle templates**
   - Get a freshly-loaded `evm/agent` template via API, assert
     `type=="template_bundle"`, `mode!=""`, `config.rules_json` is a
     non-empty JSON-encoded array string, and each sub-rule in that
     JSON has a non-empty `type`/`mode`.
   - Would have caught: file_source.go forgetting to set
     `template_bundle` + `rules_json`.

3. **Rule CRUD: created rule preserves its type all the way to the engine**
   - Create a rule with `type=evm_js` via API, list it, get it, assert
     `type` is returned. Then fire a matching sign and assert the rule
     is selected (rule_matched_id, match_count). Tests the storage +
     read-back path that broke here.

## P1 — adjacent paths the same root cause could damage

4. **All shipped bundle templates load with the right shape**
   - Walk `rules/templates/evm/*.yaml`, for each file with a top-level
     `rules:` array call template GET via API, assert
     `type=="template_bundle"` and `config.rules_json` populated. Lets
     us add new bundle templates without forgetting registry plumbing.

5. **Preset apply → list rules → match_count increments after sign**
   - Apply each shipped preset (`presets/evm/*.yaml`), fire a sign
     request matching at least one of its sub-rules, then read the
     rule list and assert `match_count >= 1` on the matching rule.
     Tests the full plane (preset + template + instance + engine +
     audit) end-to-end against the real config the user runs with.

6. **Rule re-load (Upsert idempotence + shape repair)**
   - Start server, force `template_repo.Upsert` to replay an already-
     loaded YAML. Assert the row is updated when stored type/mode
     diverge from incoming (the upsert hash fast-path we just had to
     widen).

## P2 — depth/edge cases the audit surfaced

7. **Empty/malformed bundle templates fail loudly**
   - A YAML with `rules:` but missing `type:` should NOT silently land
     with `type=""`. Either the registry sets `template_bundle` (the
     new auto-detect) or validate rejects. Lock the chosen behaviour.

8. **Rule engine "no evaluator for type" should fail-closed, not silent-skip**
   - Currently emits a `WARN` and continues iteration. Add a counter
     metric / hard error path so future "stored rule with empty type"
     bugs surface as alerts instead of "rules just don't work" for
     hours.

9. **API surfaces: `rule list` / `rule get` MUST expose `type`**
   - Today the JSON has it, but no test asserts non-empty. If the
     serializer drops it the rule engine still loads it correctly
     server-side, but the CLI surface lies. Add field-presence asserts.

10. **Preset apply with template_bundle returns expanded sub-rule list**
    - Already exists for single-rule templates (TestPreset_Apply_Success
      uses `evm_address_list`). Add a parallel test that uses a bundle
      template and asserts `applyResp.Results` has one entry per sub-rule.

## P3 — extension-side coverage that would have shortened the debug loop

11. **Live live-dapps Polymarket personal_sign asserts backend reaches `completed`**
    - The existing live test only verifies the signature recovers
      against the message. It doesn't assert what status the backend
      assigned. A staying `authorizing`/`pending` would have surfaced
      the rule-skip bug from the wallet side too.

12. **Extension popup activity drawer shows "no rule matched" diagnostic**
    - Already shows `rule_matched_id`. Extend to surface
      `last_no_match_reason` from the backend (it's logged today,
      not returned in the API). Operator sees "rule skipped: no
      evaluator for type ''" directly in the UI.

## Notes on harness

- The e2e harness is `e2e/test_server.go` + the helpers in
  `e2e_helpers.go`. Templates and presets are mounted from
  `e2e/fixtures/` via `config.e2e.yaml`. To exercise *shipped*
  templates (P1 #4 / #5), copy or symlink them under
  `e2e/fixtures/rules/` (matching the registry's expected layout).
- The agent preset references `evm/agent` template id — fixture must
  expose both for the preset to resolve.
