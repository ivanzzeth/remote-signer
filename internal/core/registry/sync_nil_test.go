//go:build integration

package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestSync_NilEntryIsAnError covers the branch the shared loop folded together.
//
// ⚠️ Each registry used to check `item == nil || item.ID == ""`. syncCatalogue
// is generic over the item type and cannot compare it to nil, so the nil check
// moved into the ident function, which returns an empty ID for a nil item. The
// two conditions become one — and this test is what says the nil half still
// works, rather than panicking on the field access.
func TestSync_NilEntryIsAnError(t *testing.T) {
	t.Run("template", func(t *testing.T) {
		if id, path := templateIdent(nil); id != "" || path != "" {
			t.Fatalf("nil template must yield empty id/path, got %q/%q", id, path)
		}
	})
	t.Run("preset", func(t *testing.T) {
		if id, path := presetIdent(nil); id != "" || path != "" {
			t.Fatalf("nil preset must yield empty id/path, got %q/%q", id, path)
		}
	})
}

// nilYieldingSource hands Sync a nil entry, which a misbehaving source can do.
type nilYieldingSource struct{}

func (nilYieldingSource) Kind() types.RuleSource { return types.RuleSourceConfig }
func (nilYieldingSource) List(context.Context) ([]*types.RuleTemplate, error) {
	return []*types.RuleTemplate{nil, {ID: "ok", SourcePath: "ok.yaml"}}, nil
}

func TestSync_NilEntryDoesNotStopTheRun(t *testing.T) {
	reg := NewTemplateRegistry(setupTemplateDB(t), nilYieldingSource{}, quietLogger())

	report, err := reg.Sync(context.Background())
	if err != nil {
		t.Fatalf("a nil entry must be reported, not returned as a fatal error: %v", err)
	}
	if len(report.Errors) != 1 {
		t.Fatalf("want exactly one recorded error, got %d", len(report.Errors))
	}
	if !strings.Contains(report.Errors[0].Err.Error(), "nil or empty ID") {
		t.Errorf("unexpected error text: %v", report.Errors[0].Err)
	}
	// ⛔ The good entry beside it must still be written: one bad row in a
	// catalogue file must not silently drop the rest of the catalogue.
	if report.Changed != 1 {
		t.Errorf("the valid entry must still sync, got Changed=%d", report.Changed)
	}
}
