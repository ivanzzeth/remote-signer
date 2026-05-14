// Package registry implements the templates/presets source-of-truth layer.
//
// Before v0.3, templates were loaded from YAML files at boot via an ad-hoc
// initializer in internal/config, and presets lived only on disk (no DB
// representation). That split made it impossible to add remote sources
// (github, http) without each call site learning about each source kind.
//
// The Registry pattern replaces both: a Source produces a list of fully
// parsed *types.RuleTemplate / *types.RulePreset (with ContentHash and
// SourcePath already populated), and the Registry runs the Sync algorithm
// — upsert-by-hash for changed rows, prune for rows missing from the
// current source. The same Sync is reused for any future source kind;
// only the Source.List implementation changes.
//
// Sync is idempotent: re-running with an unchanged source touches no rows
// (Upsert short-circuits on matching ContentHash). The Registry does not
// validate semantics deeply — that's the substituter's job. It enforces
// just enough structure to refuse to write broken rows: required fields,
// valid variable types, unique variable names.
package registry

import (
	"context"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// SyncReport summarises one Sync run for logs and the future
// `/api/v1/templates/refresh` response. Changed covers both creates and
// updates; the Registry does not distinguish them because the operator-
// visible signal is "this many rows moved" — boot logs don't need to
// disambiguate insert vs update.
type SyncReport struct {
	// Source identifies which kind ran (e.g. RuleSourceConfig). Useful
	// when multiple sources are merged into one Sync log line.
	Source types.RuleSource

	// Changed is the number of rows whose ContentHash did not match the
	// stored value (so the row was inserted or updated).
	Changed int

	// Skipped is the number of rows whose ContentHash matched (no write).
	Skipped int

	// Deleted is the number of rows present in the DB under this Source
	// that the current source no longer lists (pruned by DeleteMany).
	Deleted int

	// Errors collects per-item failures so one bad file does not block
	// the rest. The caller decides whether non-empty Errors should fail
	// startup; the Registry itself returns nil error in that case.
	Errors []SyncError
}

// SyncError pairs a per-item failure with enough provenance that the
// operator can find the offending source file. ID is best-effort: for
// parse errors the file's intended ID may not yet be known, in which
// case Path is the only useful field.
type SyncError struct {
	ID   string
	Path string
	Err  error
}

// TemplateSource is the read-only view of one origin (file directory,
// remote registry, etc.) that the Registry consumes. List returns
// fully populated *types.RuleTemplate rows — including ID, ContentHash,
// SourcePath, and Source set to Kind() — ready to be passed to
// repo.Upsert. The Source is responsible for parsing and basic shape
// validation; semantic validation (variable substitution dry-run, etc.)
// happens later.
type TemplateSource interface {
	// Kind reports the RuleSource enum value the Source represents
	// (e.g. RuleSourceConfig for file sources). Used by Sync to scope
	// the prune step to rows from this source only.
	Kind() types.RuleSource

	// List enumerates every template the source currently exposes. The
	// returned slice is the source-of-truth for one Sync cycle: rows in
	// the DB with the same Source but missing from this list get pruned.
	List(ctx context.Context) ([]*types.RuleTemplate, error)
}

// PresetSource mirrors TemplateSource for presets. Kept as a separate
// interface (rather than parameterising TemplateSource over T) because
// Go interfaces don't admit type parameters and the two have meaningfully
// different per-item validation rules — keeping them separate avoids a
// generic helper that pretends they're the same.
type PresetSource interface {
	Kind() types.RuleSource
	List(ctx context.Context) ([]*types.RulePreset, error)
}
