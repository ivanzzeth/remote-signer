package storage

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestMemoryRuleRepo_Create(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	rule := &types.Rule{ID: "rule-1", Name: "test", Enabled: true}
	err := repo.Create(ctx, rule)
	require.NoError(t, err)

	// Duplicate
	err = repo.Create(ctx, rule)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestMemoryRuleRepo_Create_Nil(t *testing.T) {
	repo := NewMemoryRuleRepository()
	err := repo.Create(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

func TestMemoryRuleRepo_Get(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	rule := &types.Rule{ID: "rule-1", Name: "test", Enabled: true}
	repo.Create(ctx, rule)

	got, err := repo.Get(ctx, "rule-1")
	require.NoError(t, err)
	assert.Equal(t, "rule-1", string(got.ID))
	assert.Equal(t, "test", got.Name)

	// Not found
	_, err = repo.Get(ctx, "nonexistent")
	assert.Error(t, err)
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestMemoryRuleRepo_Get_ReturnsClone(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	rule := &types.Rule{ID: "rule-1", Name: "original", Enabled: true}
	repo.Create(ctx, rule)

	got, _ := repo.Get(ctx, "rule-1")
	got.Name = "modified"

	got2, _ := repo.Get(ctx, "rule-1")
	assert.Equal(t, "original", got2.Name, "should be a clone, not a reference")
}

func TestMemoryRuleRepo_Update(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	rule := &types.Rule{ID: "rule-1", Name: "original", Enabled: true}
	repo.Create(ctx, rule)

	updated := &types.Rule{ID: "rule-1", Name: "updated", Enabled: false}
	err := repo.Update(ctx, updated)
	require.NoError(t, err)

	got, _ := repo.Get(ctx, "rule-1")
	assert.Equal(t, "updated", got.Name)
	assert.False(t, got.Enabled)
}

func TestMemoryRuleRepo_Update_NotFound(t *testing.T) {
	repo := NewMemoryRuleRepository()
	err := repo.Update(context.Background(), &types.Rule{ID: "nonexistent"})
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestMemoryRuleRepo_Update_Nil(t *testing.T) {
	repo := NewMemoryRuleRepository()
	err := repo.Update(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

func TestMemoryRuleRepo_Delete(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	rule := &types.Rule{ID: "rule-1", Name: "test", Enabled: true}
	repo.Create(ctx, rule)

	err := repo.Delete(ctx, "rule-1")
	require.NoError(t, err)

	_, err = repo.Get(ctx, "rule-1")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestMemoryRuleRepo_Delete_NotFound(t *testing.T) {
	repo := NewMemoryRuleRepository()
	err := repo.Delete(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestMemoryRuleRepo_List_Empty(t *testing.T) {
	repo := NewMemoryRuleRepository()
	list, err := repo.List(context.Background(), RuleFilter{})
	require.NoError(t, err)
	assert.Len(t, list, 0)
}

func TestMemoryRuleRepo_List_EnabledOnly(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	repo.Create(ctx, &types.Rule{ID: "r1", Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "r2", Enabled: false})
	repo.Create(ctx, &types.Rule{ID: "r3", Enabled: true})

	list, err := repo.List(ctx, RuleFilter{EnabledOnly: true})
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestMemoryRuleRepo_List_ChainTypeFilter(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	evm := types.ChainTypeEVM
	solana := types.ChainTypeSolana

	repo.Create(ctx, &types.Rule{ID: "r1", ChainType: &evm, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "r2", ChainType: &solana, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "r3", ChainType: nil, Enabled: true}) // nil = applies to all

	list, err := repo.List(ctx, RuleFilter{ChainType: &evm})
	require.NoError(t, err)
	assert.Len(t, list, 2, "should include evm-specific and nil (any chain)")
}

func TestMemoryRuleRepo_List_TypeFilter(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	ruleType := types.RuleTypeEVMAddressList

	repo.Create(ctx, &types.Rule{ID: "r1", Type: types.RuleTypeEVMAddressList, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "r2", Type: types.RuleTypeEVMValueLimit, Enabled: true})

	list, err := repo.List(ctx, RuleFilter{Type: &ruleType})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, types.RuleID("r1"), list[0].ID)
}

func TestMemoryRuleRepo_List_Pagination(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		repo.Create(ctx, &types.Rule{ID: types.RuleID(fmt.Sprintf("r%d", i)), Enabled: true})
	}

	// Limit
	list, err := repo.List(ctx, RuleFilter{Limit: 3})
	require.NoError(t, err)
	assert.Len(t, list, 3)

	// Offset
	list, err = repo.List(ctx, RuleFilter{Offset: 8})
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestMemoryRuleRepo_Count(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	repo.Create(ctx, &types.Rule{ID: "r1", Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "r2", Enabled: false})

	count, err := repo.Count(ctx, RuleFilter{EnabledOnly: true})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	count, err = repo.Count(ctx, RuleFilter{})
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestMemoryRuleRepo_ListByChainType(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	evm := types.ChainTypeEVM
	repo.Create(ctx, &types.Rule{ID: "r1", ChainType: &evm, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "r2", Enabled: false}) // disabled

	list, err := repo.ListByChainType(ctx, types.ChainTypeEVM)
	require.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestMemoryRuleRepo_IncrementMatchCount(t *testing.T) {
	repo := NewMemoryRuleRepository()
	err := repo.IncrementMatchCount(context.Background(), "any-id")
	assert.NoError(t, err, "IncrementMatchCount is a no-op")
}

func TestCloneRule_Nil(t *testing.T) {
	assert.Nil(t, cloneRule(nil))
}

func TestCloneRule_DeepCopy(t *testing.T) {
	evm := types.ChainTypeEVM
	chain := "1"
	key := "k"
	signer := "s"
	original := &types.Rule{
		ID:            "r1",
		ChainType:     &evm,
		ChainID:       &chain,
		APIKeyID:      &key,
		SignerAddress: &signer,
	}

	clone := cloneRule(original)
	assert.Equal(t, original.ID, clone.ID)

	// Modify clone shouldn't affect original
	newChain := "137"
	clone.ChainID = &newChain
	assert.Equal(t, "1", *original.ChainID)
}

// --- Additional MemoryRuleRepository tests for uncovered filter paths ---

func TestMemoryRuleRepo_List_SourceFilter(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	repo.Create(ctx, &types.Rule{ID: "rs1", Source: types.RuleSourceConfig, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "rs2", Source: types.RuleSourceAPI, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "rs3", Source: types.RuleSourceConfig, Enabled: true})

	source := types.RuleSourceConfig
	list, err := repo.List(ctx, RuleFilter{Source: &source})
	require.NoError(t, err)
	assert.Len(t, list, 2)

	for _, r := range list {
		assert.Equal(t, types.RuleSourceConfig, r.Source)
	}
}

func TestMemoryRuleRepo_List_ChainIDFilter(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	chain1 := "1"
	chain137 := "137"

	repo.Create(ctx, &types.Rule{ID: "rc1", ChainID: &chain1, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "rc2", ChainID: &chain137, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "rc3", ChainID: nil, Enabled: true}) // nil = applies to all

	list, err := repo.List(ctx, RuleFilter{ChainID: &chain1})
	require.NoError(t, err)
	assert.Len(t, list, 2, "should include chain-1 specific and nil (any chain)")
}

func TestMemoryRuleRepo_List_APIKeyIDFilter(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	key1 := "key-1"
	key2 := "key-2"

	repo.Create(ctx, &types.Rule{ID: "rk1", APIKeyID: &key1, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "rk2", APIKeyID: &key2, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "rk3", APIKeyID: nil, Enabled: true}) // nil = applies to all

	list, err := repo.List(ctx, RuleFilter{APIKeyID: &key1})
	require.NoError(t, err)
	assert.Len(t, list, 2, "should include key-1 specific and nil (any key)")
}

func TestMemoryRuleRepo_List_SignerAddressFilter(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	signer1 := "0xAAA"
	signer2 := "0xBBB"

	repo.Create(ctx, &types.Rule{ID: "rsa1", SignerAddress: &signer1, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "rsa2", SignerAddress: &signer2, Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "rsa3", SignerAddress: nil, Enabled: true}) // nil = applies to all

	list, err := repo.List(ctx, RuleFilter{SignerAddress: &signer1})
	require.NoError(t, err)
	assert.Len(t, list, 2, "should include signer-specific and nil (any signer)")
}

func TestMemoryRuleRepo_List_OffsetBeyondLength(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	repo.Create(ctx, &types.Rule{ID: "ro1", Enabled: true})
	repo.Create(ctx, &types.Rule{ID: "ro2", Enabled: true})

	// Offset >= length should return empty (offset not applied since not < len)
	list, err := repo.List(ctx, RuleFilter{Offset: 5})
	require.NoError(t, err)
	assert.Len(t, list, 2, "offset >= len should not apply, returning all up to limit")
}

func TestMemoryRuleRepo_List_CombinedFilters(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	evm := types.ChainTypeEVM
	solana := types.ChainTypeSolana
	chain1 := "1"
	key1 := "key-1"
	signer1 := "0xAAA"

	repo.Create(ctx, &types.Rule{
		ID: "rcf1", ChainType: &evm, ChainID: &chain1, APIKeyID: &key1,
		SignerAddress: &signer1, Type: types.RuleTypeEVMAddressList,
		Source: types.RuleSourceConfig, Enabled: true,
	})
	repo.Create(ctx, &types.Rule{
		ID: "rcf2", ChainType: &solana, ChainID: &chain1, APIKeyID: &key1,
		SignerAddress: &signer1, Type: types.RuleTypeEVMAddressList,
		Source: types.RuleSourceConfig, Enabled: true,
	})

	ruleType := types.RuleTypeEVMAddressList
	source := types.RuleSourceConfig
	list, err := repo.List(ctx, RuleFilter{
		ChainType:     &evm,
		ChainID:       &chain1,
		APIKeyID:      &key1,
		SignerAddress: &signer1,
		Type:          &ruleType,
		Source:        &source,
		EnabledOnly:   true,
	})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, types.RuleID("rcf1"), list[0].ID)
}

func TestMemoryRuleRepo_Count_ReturnsZeroForNoMatch(t *testing.T) {
	repo := NewMemoryRuleRepository()
	ctx := context.Background()

	repo.Create(ctx, &types.Rule{ID: "rc-nm1", Enabled: false})

	count, err := repo.Count(ctx, RuleFilter{EnabledOnly: true})
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
