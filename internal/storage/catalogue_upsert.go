package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ---------- the upsert both catalogue tables run ----------
//
// Templates and presets are two catalogue tables with one write path:
// Registry.Sync hands every row from the source on every boot, and the
// repository decides insert / update / skip. GormTemplateRepository.Upsert and
// GormPresetRepository.Upsert were the same 31 lines twice, down to the wording
// of five error messages.
//
// ⚠️ They were not, however, doing the same thing — and the preset copy's own
// doc comment said they were ("Mirrors TemplateRepository.Upsert exactly").
// The template copy also compares the stored type/mode, so a row written by an
// older build with type="" gets repaired even though the YAML's hash never
// moved; the preset copy skips on hash alone. That difference is real and
// deliberate (RulePreset has no type/mode), which is exactly why it belongs in
// one visible `fresh` predicate per table instead of buried in two bodies that
// claim to be identical.

// catalogueUpsert is everything upsertCatalogueRow needs to know about one
// catalogue table. One value per table, declared below, so the two tables'
// differences sit side by side and can be read in one screen.
type catalogueUpsert[T any] struct {
	// noun names the entity in every error this upsert can return
	// ("template cannot be nil", "failed to update preset").
	noun string
	// selectCols is the projection of the stored row loaded for the freshness
	// check. ⚠️ It must list every column `fresh` reads — a column left out
	// comes back zero-valued and silently compares unequal, which turns the
	// skip path into an UPDATE for every row on every boot.
	selectCols string
	id         func(*T) string
	// fresh reports whether the stored row is already current, i.e. whether
	// this Upsert can skip the write. Content hash is the cheap answer; a
	// table may demand more (see templateUpsert).
	fresh        func(existing, incoming *T) bool
	setCreatedAt func(*T, time.Time)
	setUpdatedAt func(*T, time.Time)
}

var templateUpsert = catalogueUpsert[types.RuleTemplate]{
	noun: "template",
	// type and mode are in the projection because fresh() reads them.
	selectCols: "id, content_hash, type, mode",
	id:         func(t *types.RuleTemplate) string { return t.ID },
	fresh: func(existing, incoming *types.RuleTemplate) bool {
		// Skip the write when content_hash matches AND the stored type/mode
		// agree with the incoming row. The extra type/mode guard rescues rows
		// from older registry builds that stored bundle-style templates with
		// type="" (the bundle dispatch then silently did nothing). A code
		// change in file_source.go can leave the YAML file's hash untouched
		// but still need a fresh upsert to repair the stored shape.
		return existing.ContentHash != "" && existing.ContentHash == incoming.ContentHash &&
			existing.Type == incoming.Type && existing.Mode == incoming.Mode
	},
	setCreatedAt: func(t *types.RuleTemplate, now time.Time) { t.CreatedAt = now },
	setUpdatedAt: func(t *types.RuleTemplate, now time.Time) { t.UpdatedAt = now },
}

var presetUpsert = catalogueUpsert[types.RulePreset]{
	noun:       "preset",
	selectCols: "id, content_hash",
	id:         func(p *types.RulePreset) string { return p.ID },
	// A preset carries no type/mode, so the hash is the whole answer here.
	fresh: func(existing, incoming *types.RulePreset) bool {
		return existing.ContentHash != "" && existing.ContentHash == incoming.ContentHash
	},
	setCreatedAt: func(p *types.RulePreset, now time.Time) { p.CreatedAt = now },
	setUpdatedAt: func(p *types.RulePreset, now time.Time) { p.UpdatedAt = now },
}

// upsertCatalogueRow inserts row, updates it, or skips the write when the
// stored row is already current.
//
// The skip path is why this is worth its own function: most boots see no
// catalogue change, and skipping costs one projected SELECT instead of a full
// JSON marshal plus UPDATE for every row the source lists.
func upsertCatalogueRow[T any](ctx context.Context, db *gorm.DB, row *T, spec catalogueUpsert[T]) (bool, error) {
	if row == nil {
		return false, fmt.Errorf("%s cannot be nil", spec.noun)
	}
	if spec.id(row) == "" {
		return false, fmt.Errorf("%s id is required", spec.noun)
	}

	var existing T
	err := db.WithContext(ctx).Select(spec.selectCols).
		First(&existing, "id = ?", spec.id(row)).Error
	now := time.Now()
	if err == gorm.ErrRecordNotFound {
		spec.setCreatedAt(row, now)
		spec.setUpdatedAt(row, now)
		if err := db.WithContext(ctx).Create(row).Error; err != nil {
			return false, fmt.Errorf("failed to create %s: %w", spec.noun, err)
		}
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check existing %s: %w", spec.noun, err)
	}
	if spec.fresh(&existing, row) {
		return false, nil
	}
	spec.setUpdatedAt(row, now)
	if err := db.WithContext(ctx).Save(row).Error; err != nil {
		return false, fmt.Errorf("failed to update %s: %w", spec.noun, err)
	}
	return true, nil
}
