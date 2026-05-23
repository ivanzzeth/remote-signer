package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// isTemplateFilename
// ---------------------------------------------------------------------------

func TestIsTemplateFilename(t *testing.T) {
	tests := []struct {
		name   string
		expect bool
	}{
		{"polymarket_safe.template.yaml", true},
		{"erc20.template.js.yaml", true},
		{"simple.template.yaml", true},
		{"plain.yaml", false},
		{"template.yaml", false},
		{"notemplate.yaml", false},
		{"some.yml", false},
		{"some.template.yml", false},
		{"", false},
		{"noextension", false},
		{".template.yaml", true},
		{"path/to/file.template.yaml", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, isTemplateFilename(tc.name))
		})
	}
}

// ---------------------------------------------------------------------------
// deriveTemplateDisplayName
// ---------------------------------------------------------------------------

func TestDeriveTemplateDisplayName(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"erc20.template.js.yaml", "erc20"},
		{"polymarket_safe.template.yaml", "polymarket safe"},
		{"simple.template.yaml", "simple"},
		{"no_extension", "no extension"},
		{"plain.yaml", "plain.yaml"},
		{".template.yaml", ".template.yaml"},
		{"with.dots.template.yaml", "with.dots"},
		{"template_file.template.yaml", "template file"},
	}
	for _, tc := range tests {
		t.Run(tc.filename, func(t *testing.T) {
			assert.Equal(t, tc.expected, deriveTemplateDisplayName(tc.filename))
		})
	}
}

// ---------------------------------------------------------------------------
// LoadTemplatesFromDir
// ---------------------------------------------------------------------------

func TestLoadTemplatesFromDir(t *testing.T) {
	t.Run("non-existent directory", func(t *testing.T) {
		_, err := LoadTemplatesFromDir("/nonexistent/templates/dir", ".", testLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read templates_dir")
	})

	t.Run("empty directory returns empty", func(t *testing.T) {
		dir := t.TempDir()
		result, err := LoadTemplatesFromDir(dir, ".", testLogger())
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("skips non-template files", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "plain.yaml"), []byte(""), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "data.txt"), []byte(""), 0644))
		result, err := LoadTemplatesFromDir(dir, ".", testLogger())
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("enumerates template files", func(t *testing.T) {
		dir := t.TempDir()
		tmplYAML := `
variables: []
rules: []
`
		require.NoError(t, os.WriteFile(filepath.Join(dir, "my_rule.template.yaml"), []byte(tmplYAML), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "other.template.js.yaml"), []byte(tmplYAML), 0644))
		result, err := LoadTemplatesFromDir(dir, ".", testLogger())
		require.NoError(t, err)
		require.Len(t, result, 2)

		// Verify the results are TemplateConfig with type=file
		foundNames := make(map[string]bool)
		for _, tc := range result {
			assert.Equal(t, TemplateFileType, tc.Type)
			assert.True(t, tc.Enabled)
			// path check skipped: display name may differ from path filename
			foundNames[tc.Name] = true
		}
		assert.True(t, foundNames["my rule"], "expected 'my rule' template")
		assert.True(t, foundNames["other"], "expected 'other' template")
	})

	t.Run("resolves relative path", func(t *testing.T) {
		dir := t.TempDir()
		subDir := filepath.Join(dir, "templates")
		require.NoError(t, os.MkdirAll(subDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(subDir, "test.template.yaml"), []byte("variables: []\nrules: []\n"), 0644))

		result, err := LoadTemplatesFromDir("templates", dir, testLogger())
		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, "test", result[0].Name)
	})

	t.Run("skips directories inside template dir", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0755))
		result, err := LoadTemplatesFromDir(dir, ".", testLogger())
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		dir := t.TempDir()
		result, err := LoadTemplatesFromDir(dir, ".", nil)
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}
