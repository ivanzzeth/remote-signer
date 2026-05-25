//go:build integration

package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func setupTemplateRepoTestDB(t *testing.T) (*gorm.DB, *GormTemplateRepository) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleTemplate{}))
	repo, err := NewGormTemplateRepository(db)
	require.NoError(t, err)
	return db, repo
}

func TestTemplateRepo_NewGormTemplateRepository_NilDB(t *testing.T) {
	repo, err := NewGormTemplateRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestTemplateRepo_Create(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	tmpl := &types.RuleTemplate{
		ID:      "tmpl-1",
		Name:    "Test Template",
		Type:    types.RuleTypeEVMAddressList,
		Mode:    types.RuleModeWhitelist,
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	err := repo.Create(ctx, tmpl)
	require.NoError(t, err)

	got, err := repo.Get(ctx, "tmpl-1")
	require.NoError(t, err)
	assert.Equal(t, "tmpl-1", got.ID)
	assert.Equal(t, "Test Template", got.Name)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestTemplateRepo_Create_Nil(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	err := repo.Create(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "template cannot be nil")
}

func TestTemplateRepo_Get_NotFound(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	_, err := repo.Get(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestTemplateRepo_GetByName(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	tmpl := &types.RuleTemplate{
		ID:      "tmpl-gbn-1",
		Name:    "Unique Name",
		Type:    types.RuleTypeEVMAddressList,
		Mode:    types.RuleModeWhitelist,
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, tmpl))

	got, err := repo.GetByName(ctx, "Unique Name")
	require.NoError(t, err)
	assert.Equal(t, "tmpl-gbn-1", got.ID)
}

func TestTemplateRepo_GetByName_NotFound(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	_, err := repo.GetByName(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestTemplateRepo_Update(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	tmpl := &types.RuleTemplate{
		ID:      "tmpl-upd-1",
		Name:    "Original",
		Type:    types.RuleTypeEVMAddressList,
		Mode:    types.RuleModeWhitelist,
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, tmpl))

	tmpl.Name = "Updated"
	tmpl.Enabled = false
	err := repo.Update(ctx, tmpl)
	require.NoError(t, err)

	got, _ := repo.Get(ctx, "tmpl-upd-1")
	assert.Equal(t, "Updated", got.Name)
	assert.False(t, got.Enabled)
}

func TestTemplateRepo_Update_Nil(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	err := repo.Update(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "template cannot be nil")
}

func TestTemplateRepo_Delete(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	tmpl := &types.RuleTemplate{
		ID:      "tmpl-del-1",
		Name:    "To Delete",
		Type:    types.RuleTypeEVMAddressList,
		Mode:    types.RuleModeWhitelist,
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, tmpl))

	err := repo.Delete(ctx, "tmpl-del-1")
	require.NoError(t, err)

	_, err = repo.Get(ctx, "tmpl-del-1")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestTemplateRepo_Delete_NotFound(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	err := repo.Delete(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestTemplateRepo_List(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-l1", Name: "T1", Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Enabled: true,
	}))
	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-l2", Name: "T2", Type: types.RuleTypeEVMValueLimit,
		Mode: types.RuleModeBlocklist, Source: types.RuleSourceAPI, Enabled: false,
	}))
	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-l3", Name: "T3", Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Enabled: true,
	}))

	// All templates
	list, err := repo.List(ctx, TemplateFilter{})
	require.NoError(t, err)
	assert.Len(t, list, 3)
}

func TestTemplateRepo_List_EnabledOnly(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-eo1", Name: "Enabled", Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Enabled: true,
	}))
	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-eo2", Name: "Disabled", Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Enabled: false,
	}))

	list, err := repo.List(ctx, TemplateFilter{EnabledOnly: true})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "tmpl-eo1", list[0].ID)
}

func TestTemplateRepo_List_TypeFilter(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-tf1", Name: "AddrList", Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Enabled: true,
	}))
	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-tf2", Name: "ValLimit", Type: types.RuleTypeEVMValueLimit,
		Mode: types.RuleModeBlocklist, Source: types.RuleSourceConfig, Enabled: true,
	}))

	ruleType := types.RuleTypeEVMAddressList
	list, err := repo.List(ctx, TemplateFilter{Type: &ruleType})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "tmpl-tf1", list[0].ID)
}

func TestTemplateRepo_List_SourceFilter(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-sf1", Name: "Config", Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Enabled: true,
	}))
	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-sf2", Name: "API", Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceAPI, Enabled: true,
	}))

	source := types.RuleSourceAPI
	list, err := repo.List(ctx, TemplateFilter{Source: &source})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "tmpl-sf2", list[0].ID)
}

func TestTemplateRepo_List_Pagination(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
			ID: "tmpl-pg-" + string(rune('a'+i)), Name: "T",
			Type: types.RuleTypeEVMAddressList, Mode: types.RuleModeWhitelist,
			Source: types.RuleSourceConfig, Enabled: true,
		}))
	}

	list, err := repo.List(ctx, TemplateFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, list, 2)

	list, err = repo.List(ctx, TemplateFilter{Limit: 10, Offset: 3})
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestTemplateRepo_Count(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-c1", Name: "T1", Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist, Source: types.RuleSourceConfig, Enabled: true,
	}))
	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID: "tmpl-c2", Name: "T2", Type: types.RuleTypeEVMValueLimit,
		Mode: types.RuleModeBlocklist, Source: types.RuleSourceAPI, Enabled: false,
	}))

	count, err := repo.Count(ctx, TemplateFilter{})
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	count, err = repo.Count(ctx, TemplateFilter{EnabledOnly: true})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	ruleType := types.RuleTypeEVMValueLimit
	count, err = repo.Count(ctx, TemplateFilter{Type: &ruleType})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	source := types.RuleSourceAPI
	count, err = repo.Count(ctx, TemplateFilter{Source: &source})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

// TestTemplateRepo_Upsert_HashFastPathSkipsWrite asserts that Upsert
// short-circuits when the incoming row's ContentHash already matches the
// stored row's hash AND the stored Type/Mode also agree — the Registry
// boots this loop on every server start, so the fast-path is what keeps
// startup cheap for unchanged YAMLs.
func TestTemplateRepo_Upsert_HashFastPathSkipsWrite(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	initial := &types.RuleTemplate{
		ID:          "tmpl-up-fast",
		Name:        "Stable",
		Type:        types.RuleTypeEVMAddressList,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		Enabled:     true,
		ContentHash: "hash-AAA",
	}
	changed, err := repo.Upsert(ctx, initial)
	require.NoError(t, err)
	assert.True(t, changed, "first Upsert inserts → changed=true")

	stored, err := repo.Get(ctx, "tmpl-up-fast")
	require.NoError(t, err)
	firstUpdatedAt := stored.UpdatedAt

	// Re-Upsert identical content. Type+Mode+Hash all match, fast-path
	// must fire — no UPDATE, UpdatedAt frozen.
	identical := &types.RuleTemplate{
		ID:          "tmpl-up-fast",
		Name:        "Stable",
		Type:        types.RuleTypeEVMAddressList,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		Enabled:     true,
		ContentHash: "hash-AAA",
	}
	changed, err = repo.Upsert(ctx, identical)
	require.NoError(t, err)
	assert.False(t, changed, "identical Upsert must skip the write")

	stored2, err := repo.Get(ctx, "tmpl-up-fast")
	require.NoError(t, err)
	assert.True(t, stored2.UpdatedAt.Equal(firstUpdatedAt),
		"UpdatedAt MUST be unchanged when the fast-path elides the write")
}

// TestTemplateRepo_Upsert_ShapeRepairForcesUpdate pins the storage-side
// fix for the bundle-template bug: when an older registry build stored
// a row with Type="" (the bundle dispatch then silently did nothing) and
// a code change in file_source.go now produces the correct shape WITHOUT
// touching the YAML's content hash, Upsert MUST detect the type/mode
// divergence and force the UPDATE through. Without the extra
// type/mode guard the fast-path keeps the broken row in place — that's
// the exact failure mode users hit (see commit 3d9feba). Two scenarios:
//
//  1. Stored Type is "" (legacy bundle row), incoming Type is
//     "template_bundle" — must force-update.
//  2. Stored Mode is "" / different, incoming Mode is "whitelist" — must
//     force-update.
func TestTemplateRepo_Upsert_ShapeRepairForcesUpdate(t *testing.T) {
	t.Run("repairs empty type even when hash matches", func(t *testing.T) {
		_, repo := setupTemplateRepoTestDB(t)
		ctx := context.Background()

		// Seed a "legacy" row: same hash as we're about to upsert with,
		// but stored Type="" — this is exactly the broken-bundle shape
		// the registry produced before the auto-detect fix.
		legacy := &types.RuleTemplate{
			ID:          "tmpl-up-repair-type",
			Name:        "Legacy Bundle",
			Type:        "", // ← the bug shape
			Mode:        types.RuleModeWhitelist,
			Source:      types.RuleSourceConfig,
			Enabled:     true,
			ContentHash: "hash-shared",
		}
		require.NoError(t, repo.Create(ctx, legacy))

		// Re-upsert with the SAME hash but the correct Type.
		repaired := &types.RuleTemplate{
			ID:          "tmpl-up-repair-type",
			Name:        "Legacy Bundle",
			Type:        "template_bundle", // ← repaired shape
			Mode:        types.RuleModeWhitelist,
			Source:      types.RuleSourceConfig,
			Enabled:     true,
			ContentHash: "hash-shared",
		}
		changed, err := repo.Upsert(ctx, repaired)
		require.NoError(t, err)
		assert.True(t, changed,
			"Upsert MUST force the write when stored Type='' diverges from incoming, even on matching hash — otherwise legacy bundle rows never get repaired and the engine keeps skipping them")

		got, err := repo.Get(ctx, "tmpl-up-repair-type")
		require.NoError(t, err)
		assert.Equal(t, types.RuleType("template_bundle"), got.Type,
			"stored row MUST now carry the repaired Type")
	})

	t.Run("repairs diverging mode even when hash matches", func(t *testing.T) {
		_, repo := setupTemplateRepoTestDB(t)
		ctx := context.Background()

		legacy := &types.RuleTemplate{
			ID:          "tmpl-up-repair-mode",
			Name:        "Mode Drift",
			Type:        types.RuleTypeEVMAddressList,
			Mode:        "", // ← drifted shape
			Source:      types.RuleSourceConfig,
			Enabled:     true,
			ContentHash: "hash-shared-mode",
		}
		require.NoError(t, repo.Create(ctx, legacy))

		repaired := &types.RuleTemplate{
			ID:          "tmpl-up-repair-mode",
			Name:        "Mode Drift",
			Type:        types.RuleTypeEVMAddressList,
			Mode:        types.RuleModeWhitelist, // ← repaired
			Source:      types.RuleSourceConfig,
			Enabled:     true,
			ContentHash: "hash-shared-mode",
		}
		changed, err := repo.Upsert(ctx, repaired)
		require.NoError(t, err)
		assert.True(t, changed,
			"Upsert MUST force the write when stored Mode diverges, even on matching hash")

		got, err := repo.Get(ctx, "tmpl-up-repair-mode")
		require.NoError(t, err)
		assert.Equal(t, types.RuleModeWhitelist, got.Mode,
			"stored row MUST now carry the repaired Mode")
	})
}

// TestTemplateRepo_Upsert_HashMismatchUpdates is the standard
// content-changed path. Hash differs → unconditional update, even with
// matching type/mode.
func TestTemplateRepo_Upsert_HashMismatchUpdates(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	initial := &types.RuleTemplate{
		ID:          "tmpl-up-hash-diff",
		Name:        "Original",
		Type:        types.RuleTypeEVMAddressList,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		Enabled:     true,
		ContentHash: "hash-v1",
	}
	_, err := repo.Upsert(ctx, initial)
	require.NoError(t, err)

	updated := &types.RuleTemplate{
		ID:          "tmpl-up-hash-diff",
		Name:        "Renamed",
		Type:        types.RuleTypeEVMAddressList,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		Enabled:     true,
		ContentHash: "hash-v2",
	}
	changed, err := repo.Upsert(ctx, updated)
	require.NoError(t, err)
	assert.True(t, changed, "hash drift MUST trigger an update")

	got, err := repo.Get(ctx, "tmpl-up-hash-diff")
	require.NoError(t, err)
	assert.Equal(t, "Renamed", got.Name)
	assert.Equal(t, "hash-v2", got.ContentHash)
}

// TestTemplateRepo_Upsert_InsertsWhenMissing covers the "row absent"
// branch.
func TestTemplateRepo_Upsert_InsertsWhenMissing(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	ctx := context.Background()

	tmpl := &types.RuleTemplate{
		ID:          "tmpl-up-new",
		Name:        "Brand new",
		Type:        types.RuleTypeEVMAddressList,
		Mode:        types.RuleModeWhitelist,
		Source:      types.RuleSourceConfig,
		Enabled:     true,
		ContentHash: "hash-new",
	}
	changed, err := repo.Upsert(ctx, tmpl)
	require.NoError(t, err)
	assert.True(t, changed)

	got, err := repo.Get(ctx, "tmpl-up-new")
	require.NoError(t, err)
	assert.Equal(t, "Brand new", got.Name)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

// TestTemplateRepo_Upsert_RejectsEmptyID prevents silent corruption of
// the singleton "" row (a bug that did briefly surface during shape-
// repair debugging — every YAML coalesced onto a row keyed by "").
func TestTemplateRepo_Upsert_RejectsEmptyID(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	tmpl := &types.RuleTemplate{
		Name: "Anon",
		Type: types.RuleTypeEVMAddressList,
		Mode: types.RuleModeWhitelist,
	}
	_, err := repo.Upsert(context.Background(), tmpl)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template id is required")
}

// TestTemplateRepo_Upsert_RejectsNil also locks the existing nil guard.
func TestTemplateRepo_Upsert_RejectsNil(t *testing.T) {
	_, repo := setupTemplateRepoTestDB(t)
	_, err := repo.Upsert(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template cannot be nil")
}
