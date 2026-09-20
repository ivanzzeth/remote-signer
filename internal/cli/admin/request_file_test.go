package admin

import (
	"strings"
	"testing"

	"github.com/ivanzzeth/remote-signer/pkg/client/templates"
)

// The regression this file exists for: a request written the way the API
// documents it, in the format --file advertises, must actually take effect.
//
// Before decodeRequestFile these keys bound to nothing (yaml.v3 ignores `json:`
// tags and looks for "maxtotal"/"chainid"), the file parsed, the server
// answered 200, and the resulting rule rejected everything with "budget
// exceeded" — a message that sends you to look at the limits rather than at the
// file that never applied.
func TestDecodeRequestFileHonoursDocumentedKeys(t *testing.T) {
	const doc = `
name: "native transfer"
chain_type: evm
chain_id: "56"
variables:
  allowed_recipients: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
  max_transfer_amount: "1000000000000000000"
budget:
  max_total: "1000000000000000000"
  max_per_tx: "500000000000000000"
  max_tx_count: 10000
  alert_pct: 80
schedule:
  period: 24h
`
	var req templates.InstantiateRequest
	if err := decodeRequestFile([]byte(doc), &req); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if req.ChainID == nil || *req.ChainID != "56" {
		t.Fatalf("chain_id did not bind: %v — a rule would be created on the wrong chain", req.ChainID)
	}
	if req.ChainType == nil || *req.ChainType != "evm" {
		t.Fatalf("chain_type did not bind: %v", req.ChainType)
	}
	if req.Budget == nil {
		t.Fatal("budget did not bind at all — the rule would be created with no budget row, and then reject every request")
	}
	// These four are the exact keys whose silent loss produced "budget
	// exceeded" on a brand-new rule.
	if req.Budget.MaxTotal != "1000000000000000000" {
		t.Errorf("budget.max_total = %q, want the value in the file — an empty limit is not an unlimited one, it rejects everything", req.Budget.MaxTotal)
	}
	if req.Budget.MaxPerTx != "500000000000000000" {
		t.Errorf("budget.max_per_tx = %q, want the value in the file", req.Budget.MaxPerTx)
	}
	if req.Budget.MaxTxCount != 10000 {
		t.Errorf("budget.max_tx_count = %d, want 10000 — zero means no transaction may ever pass", req.Budget.MaxTxCount)
	}
	if req.Budget.AlertPct != 80 {
		t.Errorf("budget.alert_pct = %d, want 80", req.Budget.AlertPct)
	}
	if req.Schedule == nil || req.Schedule.Period != "24h" {
		t.Fatalf("schedule.period did not bind: %+v — the budget would never reset", req.Schedule)
	}
	if req.Variables["allowed_recipients"] == "" {
		t.Error("variables did not bind")
	}
}

// --file says "YAML/JSON". JSON is a subset of YAML, so it always parsed — and
// its keys were dropped exactly the same way.
func TestDecodeRequestFileAcceptsJSON(t *testing.T) {
	const doc = `{"name":"j","chain_id":"56","budget":{"max_total":"7","max_per_tx":"7","max_tx_count":3}}`
	var req templates.InstantiateRequest
	if err := decodeRequestFile([]byte(doc), &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.ChainID == nil || *req.ChainID != "56" {
		t.Fatalf("chain_id did not bind from JSON: %v", req.ChainID)
	}
	if req.Budget == nil || req.Budget.MaxTxCount != 3 {
		t.Fatalf("budget did not bind from JSON: %+v", req.Budget)
	}
}

// A key that binds to nothing is indistinguishable from a key nobody wrote —
// which is the whole class of bug this file is about. A typo in a budget limit
// must not be the difference between a budget and no budget.
func TestDecodeRequestFileRejectsAKeyThatWouldBeIgnored(t *testing.T) {
	const doc = `
name: "typo"
budget:
  max_per_transaction: "1"
`
	var req templates.InstantiateRequest
	err := decodeRequestFile([]byte(doc), &req)
	if err == nil {
		t.Fatal("a misspelled key was accepted and silently dropped — the caller would believe a limit was set that is not there")
	}
	if !strings.Contains(err.Error(), "max_per_transaction") {
		t.Errorf("the error must name the key that did not bind, or the reader has to diff the file against the docs by hand; got: %v", err)
	}
}
