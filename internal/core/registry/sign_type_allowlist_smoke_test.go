//go:build integration

package registry

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestSignTypeAllowlistTemplate_ParsesCleanly is a content-level smoke
// check: the ship-with-the-binary off-chain demo at
// rules/templates/sign_type_allowlist.yaml must parse through the
// Registry's FileSource without errors. If a maintainer edits that
// file into invalid shape (wrong variable type, broken yaml, etc.)
// this test catches it before boot does.
//
// The full rules/templates/ tree contains legacy files that R6 will
// migrate; this test isolates just the off-chain demo by copying it
// into a tmpdir so the other files don't poison the parse.
func TestSignTypeAllowlistTemplate_ParsesCleanly(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join("..", "..", "..", "rules", "templates", "sign_type_allowlist.yaml")
	body, err := os.ReadFile(src)
	require.NoError(t, err, "demo template missing — restore rules/templates/sign_type_allowlist.yaml")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sign_type_allowlist.yaml"), body, 0o644))

	items, err := NewFileTemplateSource(dir).List(context.Background())
	require.NoError(t, err)
	require.Len(t, items, 1)

	got := items[0]
	assert.Equal(t, "sign_type_allowlist", got.ID)
	assert.Equal(t, types.ChainType(""), got.ChainType, "no subdir → off-chain")
	assert.Equal(t, "Sign-type allowlist", got.Name)
	assert.NotEmpty(t, got.Variables)
	assert.NotEmpty(t, got.Config)
	assert.NotEmpty(t, got.ContentHash)
}
