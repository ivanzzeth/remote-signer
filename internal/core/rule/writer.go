// Package rule — writer.go is the single place a rule row may be created or
// updated.
//
// # Why a chokepoint
//
// A rule is a spending authorization: it decides which transactions get signed
// without a human looking. Before this file there were eight independent write
// paths and each carried, or did not carry, its own validation. The mandatory
// check lived in internal/api/handler/validation_mandatory.go — an HTTP-layer
// policy — so every non-HTTP path bypassed it: the CLI, the startup seeder, and
// three internal services. Commit 7379347 ("enforce mandatory validation on
// preset apply and template instantiate") fixed two instances of that shape;
// the structure that produced them was left in place.
//
// The invariant is now positional rather than procedural: a malformed config
// cannot reach the database because the only door validates, not because every
// caller remembered to.
//
// # Why the interface is declared here
//
// ruleStore is defined in this package and satisfied structurally by
// storage.RuleRepository. The use-case layer says what it needs; the adapter
// happens to provide it. Importing internal/storage from here would be the
// dependency rule inverted — see cmd/archcheck/layers.go — and is what makes a
// second storage backend a wide edit rather than a narrow one.
package rule

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
)

// ruleStore is the slice of a rule repository a writer needs. Anything that can
// persist a rule satisfies it; nothing here knows about GORM, SQLite or
// transactions.
type ruleStore interface {
	Create(ctx context.Context, rule *types.Rule) error
	Update(ctx context.Context, rule *types.Rule) error
}

// Writer persists rules, validating each one first.
type Writer struct {
	store ruleStore
}

// NewWriter returns a Writer over the given store.
func NewWriter(store ruleStore) (*Writer, error) {
	if store == nil {
		return nil, fmt.Errorf("rule store is required")
	}
	return &Writer{store: store}, nil
}

// Create validates the rule and persists it as a new row.
func (w *Writer) Create(ctx context.Context, rule *types.Rule) error {
	if err := ValidateRuleForWrite(rule); err != nil {
		return err
	}
	return w.store.Create(ctx, rule)
}

// Update validates the rule and persists the change. Use it whenever the write
// carries a Config the caller built or changed.
func (w *Writer) Update(ctx context.Context, rule *types.Rule) error {
	if err := ValidateRuleForWrite(rule); err != nil {
		return err
	}
	return w.store.Update(ctx, rule)
}

// UpdateMetadata persists a change that does not touch Config — disabling a
// rule, moving its ownership, recording an approval, bumping a match count.
//
// ⛔ It deliberately does NOT validate, and that is not laziness. The first
// version of this file validated every update, and the effect was that a rule
// already malformed in the database could not be disabled: revoke returned 400
// "config.addresses is required" and the only way to stop the rule was to edit
// the row by hand. A chokepoint that blocks turning a bad rule OFF is pointed
// the wrong way — it protects the database from the operator instead of
// protecting funds from the rule.
//
// ⚠️ If your write changes Config, this is the wrong method. The distinction is
// the whole point: Create and Update guard what a rule is allowed to authorize;
// this one only moves the flags around it.
func (w *Writer) UpdateMetadata(ctx context.Context, rule *types.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule is required")
	}
	return w.store.Update(ctx, rule)
}

// ValidateRuleForWrite is the check every write goes through. Exported so the
// paths that cannot yet take a Writer — those inside a repository transaction,
// which hand out their own store handle — can run the same check rather than an
// approximation of it.
//
// ⛔ If you are about to write a rule without calling this, you are opening the
// ninth write path. Take a Writer instead.
func ValidateRuleForWrite(rule *types.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule is required")
	}
	if rule.Type == "" {
		return fmt.Errorf("rule %s: type is required", rule.ID)
	}
	// ⚠️ Validate the EFFECTIVE config, not the stored one.
	//
	// Instance rules persist their Config in template form — `${token_address}`
	// stays a placeholder — and the engine substitutes Variables at evaluation,
	// so that editing Variables takes effect with no rendered snapshot able to
	// drift. Handing the stored bytes to the type validator therefore fails on
	// every instance rule ("${target_address} is not a valid Ethereum address"),
	// which is what the first version of this file did.
	//
	// EffectiveRule is the same resolution the engine applies, so what gets
	// validated here is what will actually be evaluated. chainID is empty: the
	// rule's own ChainID is used when it has one, and a matrix rule is checked
	// against its base variables. A per-chain matrix row that is malformed on
	// one chain only is beyond what a write-time check can see — that is what
	// the template's test_cases are for.
	eff := EffectiveRule(rule, "")
	cfg := map[string]interface{}{}
	if len(eff.Config) > 0 {
		if err := json.Unmarshal(eff.Config, &cfg); err != nil {
			return fmt.Errorf("rule %s: config is not a JSON object: %w", rule.ID, err)
		}
	}
	if err := ruleconfig.ValidateRuleConfig(string(rule.Type), cfg); err != nil {
		return fmt.Errorf("rule %s: %w", rule.ID, err)
	}
	return nil
}
