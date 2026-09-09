package rule

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

type recordingStore struct {
	created, updated int
	err              error
}

func (s *recordingStore) Create(context.Context, *types.Rule) error { s.created++; return s.err }
func (s *recordingStore) Update(context.Context, *types.Rule) error { s.updated++; return s.err }

func validRule() *types.Rule {
	return &types.Rule{
		ID:     "r1",
		Type:   types.RuleTypeEVMValueLimit,
		Config: []byte(`{"max_value":"1000000000000000000"}`),
	}
}

// The point of the chokepoint: a malformed config cannot reach the store,
// whichever caller is holding the Writer. Before 2026-09-10 the mandatory check
// lived in the HTTP handler, so the CLI, the startup seeder and three internal
// services each wrote whatever they had built.
func TestWriter_RejectsInvalidConfigBeforeItReachesTheStore(t *testing.T) {
	store := &recordingStore{}
	w, err := NewWriter(store)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	bad := validRule()
	bad.Config = []byte(`{"max_value":"not a number"}`)

	if err := w.Create(context.Background(), bad); err == nil {
		t.Fatal("expected Create to reject an invalid config")
	}
	if store.created != 0 {
		t.Fatalf("store was written %d times despite the config being invalid", store.created)
	}

	if err := w.Update(context.Background(), bad); err == nil {
		t.Fatal("expected Update to reject an invalid config")
	}
	if store.updated != 0 {
		t.Fatalf("store was updated %d times despite the config being invalid", store.updated)
	}
}

func TestWriter_PassesValidRulesThrough(t *testing.T) {
	store := &recordingStore{}
	w, _ := NewWriter(store)

	if err := w.Create(context.Background(), validRule()); err != nil {
		t.Fatalf("Create of a valid rule: %v", err)
	}
	if err := w.Update(context.Background(), validRule()); err != nil {
		t.Fatalf("Update of a valid rule: %v", err)
	}
	if store.created != 1 || store.updated != 1 {
		t.Fatalf("created=%d updated=%d, want 1 and 1", store.created, store.updated)
	}
}

func TestWriter_SurfacesStoreErrors(t *testing.T) {
	want := errors.New("boom")
	w, _ := NewWriter(&recordingStore{err: want})
	if err := w.Create(context.Background(), validRule()); !errors.Is(err, want) {
		t.Fatalf("err = %v, want the store's error", err)
	}
}

// An absent config is not waved through — it is handed to the type's validator,
// which decides. signer_restriction requires allowed_signers, so a rule of that
// type with no config is rejected here rather than becoming a rule that
// auto-approves for nobody, or for everybody, depending on how the engine reads
// an empty allowlist.
//
// ⛔ Do not "fix" this by returning early on len(Config) == 0. That would let
// exactly the rules with no constraints in them past the chokepoint.
func TestValidateRuleForWrite_EmptyConfigIsTheTypeValidatorsCall(t *testing.T) {
	r := &types.Rule{ID: "r2", Type: types.RuleTypeSignerRestriction}
	err := ValidateRuleForWrite(r)
	if err == nil {
		t.Fatal("signer_restriction with no allowed_signers should be rejected")
	}
	if !strings.Contains(err.Error(), "allowed_signers") {
		t.Fatalf("error should name the missing field, got: %v", err)
	}
}

func TestValidateRuleForWrite_RejectsUnparseableConfig(t *testing.T) {
	r := &types.Rule{ID: "r3", Type: types.RuleTypeEVMValueLimit, Config: []byte(`not json`)}
	if err := ValidateRuleForWrite(r); err == nil {
		t.Fatal("expected an unparseable config to be rejected")
	}
}

func TestNewWriter_RequiresAStore(t *testing.T) {
	if _, err := NewWriter(nil); err == nil {
		t.Fatal("expected NewWriter(nil) to fail rather than produce a Writer that panics later")
	}
}
