package registry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// quietLogger returns a discarded slog so test output stays focused on
// the assertions, not Registry's normal Info chatter.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func setupTemplateDB(t *testing.T) *storage.GormTemplateRepository {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RuleTemplate{}))
	repo, err := storage.NewGormTemplateRepository(db)
	require.NoError(t, err)
	return repo
}

func setupPresetDB(t *testing.T) *storage.GormPresetRepository {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RulePreset{}))
	repo, err := storage.NewGormPresetRepository(db)
	require.NoError(t, err)
	return repo
}

// ---------------------------------------------------------------------------
// In-memory sources for Sync-level tests (no filesystem)
// ---------------------------------------------------------------------------

type memTemplateSource struct {
	kind  types.RuleSource
	items []*types.RuleTemplate
	err   error
}

func (m *memTemplateSource) Kind() types.RuleSource { return m.kind }
func (m *memTemplateSource) List(_ context.Context) ([]*types.RuleTemplate, error) {
	return m.items, m.err
}

type memPresetSource struct {
	kind  types.RuleSource
	items []*types.RulePreset
	err   error
}

func (m *memPresetSource) Kind() types.RuleSource { return m.kind }
func (m *memPresetSource) List(_ context.Context) ([]*types.RulePreset, error) {
	return m.items, m.err
}

// ---------------------------------------------------------------------------
// TemplateRegistry.Sync
// ---------------------------------------------------------------------------

func TestTemplateRegistry_Sync_CreatesOnFirstRun(t *testing.T) {
	repo := setupTemplateDB(t)
	src := &memTemplateSource{
		kind: types.RuleSourceFile,
		items: []*types.RuleTemplate{
			{ID: "evm/erc20", Name: "ERC20", ContentHash: "h1", Source: types.RuleSourceFile},
			{ID: "evm/safe", Name: "Safe", ContentHash: "h2", Source: types.RuleSourceFile},
		},
	}
	reg := NewTemplateRegistry(repo, src, quietLogger())

	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, rep.Changed)
	assert.Equal(t, 0, rep.Skipped)
	assert.Equal(t, 0, rep.Deleted)
	assert.Empty(t, rep.Errors)
}

func TestTemplateRegistry_Sync_SkipsUnchangedRows(t *testing.T) {
	// Same source list, second pass — every row's ContentHash matches
	// the stored value, so Upsert should short-circuit to no writes.
	repo := setupTemplateDB(t)
	src := &memTemplateSource{
		kind: types.RuleSourceFile,
		items: []*types.RuleTemplate{
			{ID: "evm/x", Name: "X", ContentHash: "abc", Source: types.RuleSourceFile},
		},
	}
	reg := NewTemplateRegistry(repo, src, quietLogger())

	_, err := reg.Sync(context.Background())
	require.NoError(t, err)

	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, rep.Changed, "no writes on second pass")
	assert.Equal(t, 1, rep.Skipped)
}

func TestTemplateRegistry_Sync_UpdatesOnHashChange(t *testing.T) {
	repo := setupTemplateDB(t)
	src := &memTemplateSource{
		kind: types.RuleSourceFile,
		items: []*types.RuleTemplate{
			{ID: "evm/x", Name: "v1", ContentHash: "h1", Source: types.RuleSourceFile},
		},
	}
	reg := NewTemplateRegistry(repo, src, quietLogger())
	_, err := reg.Sync(context.Background())
	require.NoError(t, err)

	// Edit the item — hash changes, Sync must re-upsert.
	src.items[0] = &types.RuleTemplate{ID: "evm/x", Name: "v2", ContentHash: "h2", Source: types.RuleSourceFile}
	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Changed)

	got, err := repo.Get(context.Background(), "evm/x")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Name, "DB row reflects new content")
}

func TestTemplateRegistry_Sync_PrunesMissingRows(t *testing.T) {
	repo := setupTemplateDB(t)
	src := &memTemplateSource{
		kind: types.RuleSourceFile,
		items: []*types.RuleTemplate{
			{ID: "evm/a", Name: "A", ContentHash: "h", Source: types.RuleSourceFile},
			{ID: "evm/b", Name: "B", ContentHash: "h", Source: types.RuleSourceFile},
		},
	}
	reg := NewTemplateRegistry(repo, src, quietLogger())
	_, err := reg.Sync(context.Background())
	require.NoError(t, err)

	// Drop "evm/b" from the source — Sync should prune it.
	src.items = src.items[:1]
	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Deleted)

	_, err = repo.Get(context.Background(), "evm/b")
	require.Error(t, err, "pruned row no longer queryable")
}

func TestTemplateRegistry_Sync_DoesNotPruneOtherSources(t *testing.T) {
	// Templates with Source=api must survive a config-source Sync —
	// otherwise the user-created rows get wiped on every boot.
	repo := setupTemplateDB(t)
	apiRow := &types.RuleTemplate{
		ID: "user/custom", Name: "Custom", ContentHash: "h", Source: types.RuleSourceAPI,
	}
	require.NoError(t, repo.Create(context.Background(), apiRow))

	src := &memTemplateSource{
		kind:  types.RuleSourceFile,
		items: nil, // empty config source
	}
	reg := NewTemplateRegistry(repo, src, quietLogger())
	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, rep.Deleted, "api-sourced row outside config scope")

	got, err := repo.Get(context.Background(), "user/custom")
	require.NoError(t, err)
	assert.Equal(t, "Custom", got.Name)
}

func TestTemplateRegistry_Sync_DuplicateIDInSourceRecorded(t *testing.T) {
	// Two files at different paths could both collapse to ID "evm/x"
	// (e.g. evm/x.yaml and evm/x.yml). The Registry must record an
	// error rather than silently overwrite — both files need to be on
	// the operator's radar.
	repo := setupTemplateDB(t)
	src := &memTemplateSource{
		kind: types.RuleSourceFile,
		items: []*types.RuleTemplate{
			{ID: "evm/x", Name: "A", ContentHash: "h1", Source: types.RuleSourceFile, SourcePath: "evm/x.yaml"},
			{ID: "evm/x", Name: "B", ContentHash: "h2", Source: types.RuleSourceFile, SourcePath: "evm/x.yml"},
		},
	}
	reg := NewTemplateRegistry(repo, src, quietLogger())

	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Changed, "first occurrence upserted")
	require.Len(t, rep.Errors, 1)
	assert.Contains(t, rep.Errors[0].Err.Error(), "duplicate ID")
	assert.Equal(t, "evm/x.yml", rep.Errors[0].Path)
}

func TestTemplateRegistry_Sync_SourceErrorBubbles(t *testing.T) {
	repo := setupTemplateDB(t)
	src := &memTemplateSource{kind: types.RuleSourceFile, err: errors.New("source kaboom")}
	reg := NewTemplateRegistry(repo, src, quietLogger())

	_, err := reg.Sync(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "source list")
	assert.Contains(t, err.Error(), "source kaboom")
}

func TestTemplateRegistry_Sync_EmptyIDRecordedAsError(t *testing.T) {
	repo := setupTemplateDB(t)
	src := &memTemplateSource{
		kind: types.RuleSourceFile,
		items: []*types.RuleTemplate{
			{ID: "", Name: "Anon", ContentHash: "h", Source: types.RuleSourceFile},
		},
	}
	reg := NewTemplateRegistry(repo, src, quietLogger())
	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	require.Len(t, rep.Errors, 1)
	assert.Contains(t, rep.Errors[0].Err.Error(), "empty ID")
}

// ---------------------------------------------------------------------------
// PresetRegistry.Sync (same shape, mostly smoke-level)
// ---------------------------------------------------------------------------

func TestPresetRegistry_Sync_CreateThenSkipThenDelete(t *testing.T) {
	repo := setupPresetDB(t)
	src := &memPresetSource{
		kind: types.RuleSourceFile,
		items: []*types.RulePreset{
			{ID: "evm/p1", Name: "P1", ContentHash: "h", Source: types.RuleSourceFile},
			{ID: "evm/p2", Name: "P2", ContentHash: "h", Source: types.RuleSourceFile},
		},
	}
	reg := NewPresetRegistry(repo, src, quietLogger())

	// First pass — both create.
	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, rep.Changed)

	// Second pass — same hashes, no writes.
	rep, err = reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, rep.Changed)
	assert.Equal(t, 2, rep.Skipped)

	// Third pass — drop p2.
	src.items = src.items[:1]
	rep, err = reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Deleted)
}

func TestPresetRegistry_Sync_SourceErrorBubbles(t *testing.T) {
	repo := setupPresetDB(t)
	src := &memPresetSource{kind: types.RuleSourceFile, err: errors.New("kaboom")}
	reg := NewPresetRegistry(repo, src, quietLogger())
	_, err := reg.Sync(context.Background())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// End-to-end: FileSource → Registry → repo
// ---------------------------------------------------------------------------

func TestTemplateRegistry_EndToEnd_FileSource(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "evm/erc20.yaml", `
name: ERC20
type: evm_address_list
mode: whitelist
variables:
  - {name: recipient, type: address, required: true}
`)
	writeFile(t, dir, "evm/safe.yaml", `
name: Safe
type: evm_address_list
mode: whitelist
variables: []
`)

	repo := setupTemplateDB(t)
	reg := NewTemplateRegistry(repo, NewFileTemplateSource(dir), quietLogger())

	rep, err := reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, rep.Changed)

	// Stored rows have file-derived IDs and chain types.
	got, err := repo.Get(context.Background(), "evm/erc20")
	require.NoError(t, err)
	assert.Equal(t, types.ChainType("evm"), got.ChainType)
	assert.NotEmpty(t, got.ContentHash)

	// Re-run with no changes → all skipped.
	rep, err = reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, rep.Changed)
	assert.Equal(t, 2, rep.Skipped)

	// Delete one file → next Sync prunes it.
	require.NoError(t, os.Remove(filepath.Join(dir, "evm/safe.yaml")))
	rep, err = reg.Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, rep.Deleted)
	_, err = repo.Get(context.Background(), "evm/safe")
	require.Error(t, err)
}
