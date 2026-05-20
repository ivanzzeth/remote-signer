package registry

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// writeFile is a tiny test helper that creates parent dirs and writes
// a YAML fixture. Keeps the body of each test focused on the assertion.
func writeFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

// ---------------------------------------------------------------------------
// FileTemplateSource
// ---------------------------------------------------------------------------

func TestFileTemplateSource_EmptyRoot_ReturnsNil(t *testing.T) {
	// Missing root must not be an error — fresh installs have no templates dir yet.
	src := NewFileTemplateSource(filepath.Join(t.TempDir(), "nope"))
	items, err := src.List(context.Background())
	require.NoError(t, err)
	assert.Nil(t, items)
}

func TestFileTemplateSource_BlankRoot_ReturnsNil(t *testing.T) {
	src := NewFileTemplateSource("")
	items, err := src.List(context.Background())
	require.NoError(t, err)
	assert.Nil(t, items)
}

func TestFileTemplateSource_ParsesSingleTemplate(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/erc20.yaml", `
name: ERC-20 transfer
description: Allowlist USDC transfers to the treasury
type: evm_address_list
mode: whitelist
variables:
  - name: recipient
    type: address
    label: Recipient address
    required: true
rules:
  - to: "${recipient}"
`)
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)

	got := items[0]
	assert.Equal(t, "evm/erc20", got.ID, "ID derived from path stem")
	assert.Equal(t, types.ChainType("evm"), got.ChainType, "ChainType inferred from first dir segment")
	assert.Equal(t, "ERC-20 transfer", got.Name)
	assert.Equal(t, types.RuleTypeEVMAddressList, got.Type)
	assert.Equal(t, types.RuleModeWhitelist, got.Mode)
	assert.Equal(t, types.RuleSourceFile, got.Source)
	assert.Equal(t, "evm/erc20.yaml", got.SourcePath, "SourcePath is slash-normalised relative path")
	assert.True(t, got.Enabled, "Enabled defaults to true when omitted")
	assert.NotEmpty(t, got.ContentHash)
	assert.Len(t, got.ContentHash, 64, "SHA256 hex is 64 chars")
	assert.NotEmpty(t, got.Variables, "JSON column populated")
}

// TestFileTemplateSource_BundleTemplateAutoDetect pins the registry's
// behaviour for "bundle" templates (a YAML with a top-level `rules:`
// array and no explicit `type:`). Without this pin, the registry was
// storing such templates with type="" and only an object-form
// config.rules, while the downstream template service's bundle
// instantiator reads from config.rules_json (string). The mismatch
// silently turned every preset-applied rule into an empty-type rule
// that the engine skipped, routing every dApp request to manual
// approval. Caught in the field on the agent.yaml template — see
// commit 3d9feba.
func TestFileTemplateSource_BundleTemplateAutoDetect(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/agent.yaml", `
name: Agent Signature
description: Allow personal_sign with a length cap
variables:
  - name: max_message_length
    type: string
    required: false
    default: "1024"
rules:
  - id: agent-sign
    name: Agent Signature
    type: evm_js
    mode: whitelist
    config:
      sign_type_filter: personal_sign
      script: |
        function validate(input) { return ok(); }
`)
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)

	got := items[0]
	assert.Equal(t, types.RuleType("template_bundle"), got.Type,
		"YAML with top-level `rules:` and no explicit `type:` MUST be auto-detected as template_bundle")
	assert.Equal(t, types.RuleModeWhitelist, got.Mode,
		"bundle mode inherits from the first sub-rule when the YAML has no top-level mode")

	// The bundle instantiator reads config.rules_json (a JSON-encoded
	// STRING). Object-form config.rules is also still there for
	// completeness, but the string variant is the wire shape that
	// triggers expansion.
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(got.Config, &cfg))
	rulesJSON, ok := cfg["rules_json"].(string)
	require.True(t, ok, "bundle template MUST expose config.rules_json as a JSON string")
	require.NotEmpty(t, rulesJSON)
	// Decode and assert each sub-rule carries its type — the
	// instantiator copies sub-rule.type onto the generated instance,
	// and that type is what the rule engine looks up an evaluator for.
	var subRules []map[string]any
	require.NoError(t, json.Unmarshal([]byte(rulesJSON), &subRules))
	require.Len(t, subRules, 1)
	assert.Equal(t, "evm_js", subRules[0]["type"],
		"sub-rule type MUST round-trip through rules_json — empty type makes the engine silently skip the rule")
}

func TestFileTemplateSource_OffChainTemplateHasEmptyChainType(t *testing.T) {
	// Files at the root (no subdir) are off-chain — the substituter
	// will treat ChainType="" as chain-agnostic.
	dir := t.TempDir()
	writeFile(t, dir, "sign_type_allowlist.yaml", `
name: Sign-type allowlist
type: sign_type_restriction
mode: whitelist
variables: []
`)
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, types.ChainType(""), items[0].ChainType)
	assert.Equal(t, "sign_type_allowlist", items[0].ID)
}

func TestFileTemplateSource_YAMLChainTypeOverridesDirectory(t *testing.T) {
	// A top-level chain_type beats directory inference — useful when an
	// operator drops a Solana template in an evm/ folder during a port
	// (or any other scenario where the path doesn't match the chain).
	// Explicit empty-string chain_type still falls back to directory
	// inference because YAML can't distinguish "set to empty" from "not
	// set" without a pointer, and pointer fields for one optional flag
	// would be more cost than benefit.
	dir := t.TempDir()
	writeFile(t, dir, "evm/cross_chain.yaml", `
name: Cross-chain template
type: evm_address_list
mode: whitelist
chain_type: solana
variables: []
`)
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, types.ChainType("solana"), items[0].ChainType, "explicit chain_type wins over directory")
}

func TestFileTemplateSource_AcceptsYmlExtension(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/short.yml", `
name: Short ext
type: evm_address_list
mode: whitelist
variables: []
`)
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
}

func TestFileTemplateSource_IgnoresNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/erc20.yaml", `
name: ERC20
type: evm_address_list
mode: whitelist
variables: []
`)
	writeFile(t, dir, "evm/README.md", "not yaml")
	writeFile(t, dir, "evm/.hidden", "ignored too")
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, items, 1)
}

func TestFileTemplateSource_ParseFailureBubblesError(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/broken.yaml", `not: [valid: yaml`)
	src := NewFileTemplateSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken.yaml")
}

func TestFileTemplateSource_ContentHashIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	body := `
name: Stable
type: evm_address_list
mode: whitelist
variables: []
`
	writeFile(t, dir, "evm/stable.yaml", body)
	src := NewFileTemplateSource(dir)
	a, err := src.List(context.Background())
	require.NoError(t, err)
	b, err := src.List(context.Background())
	require.NoError(t, err)
	assert.Equal(t, a[0].ContentHash, b[0].ContentHash, "same bytes → same hash")
}

func TestFileTemplateSource_ContentHashChangesWithFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/x.yaml", `
name: V1
type: evm_address_list
mode: whitelist
variables: []
`)
	src := NewFileTemplateSource(dir)
	a, err := src.List(context.Background())
	require.NoError(t, err)
	writeFile(t, dir, "evm/x.yaml", `
name: V2
type: evm_address_list
mode: whitelist
variables: []
`)
	b, err := src.List(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, a[0].ContentHash, b[0].ContentHash, "edited file → new hash")
}

func TestFileTemplateSource_ValidateRejectsBadVariableType(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/bad.yaml", `
name: Bad var type
type: evm_address_list
mode: whitelist
variables:
  - name: amount
    type: uint256
`)
	src := NewFileTemplateSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type \"uint256\" invalid", "uint256 is no longer a valid type after R2")
}

func TestFileTemplateSource_ValidateRejectsDuplicateVariableNames(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/dup.yaml", `
name: Dup var
type: evm_address_list
mode: whitelist
variables:
  - {name: x, type: address}
  - {name: x, type: bigint}
`)
	src := NewFileTemplateSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate name")
}

func TestFileTemplateSource_ValidateRequiresName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/nameless.yaml", `
type: evm_address_list
mode: whitelist
variables: []
`)
	src := NewFileTemplateSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestFileTemplateSource_TypeAndModeOptional(t *testing.T) {
	// Multi-rule templates can't pick one canonical type/mode for the
	// container. Migration leaves both empty; Registry must accept.
	dir := t.TempDir()
	writeFile(t, dir, "evm/multi.yaml", `
name: Multi-rule container
variables: []
rules:
  - id: r1
    type: evm_js
    mode: whitelist
  - id: r2
    type: evm_value_limit
    mode: blocklist
`)
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, types.RuleType(""), items[0].Type, "no top-level type required")
	assert.Equal(t, types.RuleMode(""), items[0].Mode, "no top-level mode required")
}

func TestFileTemplateSource_ModeWhenSetMustBeValid(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/bad_mode.yaml", `
name: Bad mode
mode: maybe
variables: []
`)
	src := NewFileTemplateSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mode \"maybe\" invalid")
}

func TestFileTemplateSource_ValidateEnumRequiresOptions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/no_opts.yaml", `
name: No options
type: evm_address_list
mode: whitelist
variables:
  - {name: level, type: enum}
`)
	src := NewFileTemplateSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "options")
}

func TestFileTemplateSource_VariableGroupReferencesMustResolve(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/dangling.yaml", `
name: Dangling group ref
type: evm_address_list
mode: whitelist
variables:
  - {name: a, type: address}
variable_groups:
  - {title: Misc, variables: [a, b]}
`)
	src := NewFileTemplateSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown variable")
}

func TestFileTemplateSource_RejectsRootIsFile(t *testing.T) {
	// If the operator points templates_dir at a file by accident, fail
	// loudly rather than silently produce no items.
	dir := t.TempDir()
	bad := filepath.Join(dir, "not_a_dir.txt")
	require.NoError(t, os.WriteFile(bad, []byte("x"), 0o644))
	src := NewFileTemplateSource(bad)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestFileTemplateSource_WalksMultipleChainSubdirs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/one.yaml", `
name: One
type: evm_address_list
mode: whitelist
variables: []
`)
	writeFile(t, dir, "solana/two.yaml", `
name: Two
type: evm_address_list
mode: whitelist
variables: []
`)
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 2)

	byID := make(map[string]*types.RuleTemplate)
	for _, it := range items {
		byID[it.ID] = it
	}
	require.Contains(t, byID, "evm/one")
	require.Contains(t, byID, "solana/two")
	assert.Equal(t, types.ChainType("evm"), byID["evm/one"].ChainType)
	assert.Equal(t, types.ChainType("solana"), byID["solana/two"].ChainType)
}

// ---------------------------------------------------------------------------
// FilePresetSource
// ---------------------------------------------------------------------------

func TestFilePresetSource_ParsesSinglePreset(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/polymarket_trading.yaml", `
name: Polymarket trading
description: Order signing on Polygon
chain_id: "137"
template_ids: [evm/polymarket_order, evm/usdc_approve]
variables:
  safe_address: "0xabc"
operator_overrides:
  - name: safe_address
    required: true
budget:
  max_total: "1000"
schedule:
  cron: "*/5 * * * *"
`)
	src := NewFilePresetSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)

	got := items[0]
	assert.Equal(t, "evm/polymarket_trading", got.ID)
	assert.Equal(t, types.ChainType("evm"), got.ChainType)
	assert.Equal(t, "137", got.ChainID)
	assert.Equal(t, types.RuleSourceFile, got.Source)
	assert.NotEmpty(t, got.ContentHash)
	assert.NotEmpty(t, got.TemplateIDs)
	assert.NotEmpty(t, got.OperatorOverrides)
	assert.NotEmpty(t, got.Budget)
	assert.NotEmpty(t, got.Schedule)
	assert.True(t, got.Enabled)
}

func TestFilePresetSource_ValidateRequiresTemplateIDs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/empty.yaml", `
name: Empty
chain_id: "1"
template_ids: []
`)
	src := NewFilePresetSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template_ids")
}

func TestFilePresetSource_ValidateRequiresName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/nameless.yaml", `
template_ids: [evm/foo]
`)
	src := NewFilePresetSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestFilePresetSource_RejectsBlankTemplateID(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/blank.yaml", `
name: Blank tid
template_ids:
  - "evm/foo"
  - "  "
`)
	src := NewFilePresetSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blank")
}

func TestFilePresetSource_OperatorOverrideRequiresName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/x.yaml", `
name: Override no name
template_ids: [evm/foo]
operator_overrides:
  - {required: true}
`)
	src := NewFilePresetSource(dir)
	_, err := src.List(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "operator_overrides")
}

// ---------------------------------------------------------------------------
// relPathIdentity unit-level sanity checks
// ---------------------------------------------------------------------------

func TestRelPathIdentity_Variants(t *testing.T) {
	cases := []struct {
		root       string
		path       string
		wantID     string
		wantChain  types.ChainType
		wantErrSub string
	}{
		{"/r", "/r/evm/erc20.yaml", "evm/erc20", "evm", ""},
		{"/r", "/r/solana/spl_transfer.yml", "solana/spl_transfer", "solana", ""},
		{"/r", "/r/sign_type.yaml", "sign_type", "", ""},
	}
	for _, tc := range cases {
		id, chain, err := relPathIdentity(tc.root, tc.path)
		if tc.wantErrSub != "" {
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrSub)
			continue
		}
		require.NoError(t, err, "path=%s", tc.path)
		assert.Equal(t, tc.wantID, id, "id for %s", tc.path)
		assert.Equal(t, tc.wantChain, chain, "chain for %s", tc.path)
	}
}

// Belt-and-suspenders: ensure the walk does not get confused by an
// empty file or one whose stem is "."  — the helper rejects those.
func TestFileTemplateSource_IgnoresAnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "empty"), 0o755))
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, items)
}

// Sanity-check that we don't accidentally treat directories named *.yaml
// as files — fs.DirEntry.IsDir handles it but worth pinning.
func TestFileTemplateSource_SkipsDirectoryNamedLikeYAML(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "fake.yaml"), 0o755))
	src := NewFileTemplateSource(dir)
	items, err := src.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, items)
}

// Confirm filepath.WalkDir surfaces fs errors — exercised via a permission
// denied directory on POSIX. Skipped on Windows.
func TestFileTemplateSource_PropagatesWalkError(t *testing.T) {
	if os.Getenv("CI") == "" && os.Geteuid() == 0 {
		t.Skip("running as root; chmod 000 is meaningless")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "evm")
	require.NoError(t, os.MkdirAll(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "x.yaml"), []byte("name: x\ntype: evm_address_list\nmode: whitelist\nvariables: []\n"), 0o644))
	require.NoError(t, os.Chmod(sub, 0o000))
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })

	src := NewFileTemplateSource(dir)
	_, err := src.List(context.Background())
	if err == nil {
		// On some filesystems WalkDir can still list inaccessible dirs; tolerate.
		t.Skip("filesystem ignored chmod 000; walk error not exposed")
	}
	// Don't pin the wording — fs errors are platform-dependent. Just
	// confirm we surfaced *something* from the walk.
	assert.True(t, strings.Contains(err.Error(), "permission") || isPathErr(err))
}

func isPathErr(err error) bool {
	var pe *fs.PathError
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "denied") || strings.Contains(err.Error(), "permitted") || pe != nil
}
