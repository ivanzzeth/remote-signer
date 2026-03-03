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
