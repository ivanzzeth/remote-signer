package validate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ─────────────────────────────────────────────────────────────────────────────
// IsValidHexData
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidHexData(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty string", "", true},
		{"0x only", "0x", true},
		{"valid short", "0xab", true},
		{"valid long", "0xabcdef1234567890", true},
		{"valid transfer calldata", "0xa9059cbb0000000000000000000000001234567890abcdef1234567890abcdef12345678", true},
		{"odd length hex", "0xabc", false},
		{"no prefix", "abcdef", false},
		{"invalid chars", "0xzzzz", false},
		{"uppercase valid", "0xABCD", true},
		{"mixed case", "0xAbCd", true},
		{"just numbers", "0x1234", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidHexData(tc.input), "IsValidHexData(%q)", tc.input)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidHexValue
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidHexValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty string", "", true},
		{"0x0", "0x0", true},
		{"simple value", "0x1", true},
		{"large value", "0xde0b6b3a7640000", true},
		{"no prefix", "1234", false},
		{"invalid chars", "0xGHIJ", false},
		{"uppercase", "0xABCDEF", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidHexValue(tc.input), "IsValidHexValue(%q)", tc.input)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidChainID
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidChainID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"mainnet", "1", true},
		{"polygon", "137", true},
		{"large chain id", "42161", true},
		{"zero", "0", false},
		{"negative", "-1", false},
		{"empty", "", false},
		{"hex", "0x1", false},
		{"decimal with leading zero", "01", false},
		{"float", "1.0", false},
		{"letters", "abc", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidChainID(tc.input), "IsValidChainID(%q)", tc.input)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidNumericValue
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidNumericValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", true},
		{"zero", "0", true},
		{"hex zero", "0x0", true},
		{"decimal", "21000", true},
		{"large decimal", "1000000000000000000", true},
		{"hex value", "0x5208", true},
		{"hex large", "0xde0b6b3a7640000", true},
		{"negative", "-1", false},
		{"float", "1.5", false},
		{"letters only", "abc", false},
		{"mixed", "100abc", false},
		{"0X prefix not valid", "0XABC", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidNumericValue(tc.input), "IsValidNumericValue(%q)", tc.input)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// IsValidAuditSeverity
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidAuditSeverity(t *testing.T) {
	assert.True(t, IsValidAuditSeverity("info"))
	assert.True(t, IsValidAuditSeverity("warning"))
	assert.True(t, IsValidAuditSeverity("critical"))
	assert.False(t, IsValidAuditSeverity(""))
	assert.False(t, IsValidAuditSeverity("error"))
	assert.False(t, IsValidAuditSeverity("INFO"))
}

// ─────────────────────────────────────────────────────────────────────────────
// ValidateJSCodeSecurity
// ─────────────────────────────────────────────────────────────────────────────

func TestValidateJSCodeSecurity(t *testing.T) {
	t.Run("safe code passes", func(t *testing.T) {
		code := `function evaluate(tx) { return tx.to === "0x1234"; }`
		assert.NoError(t, ValidateJSCodeSecurity(code))
	})

	t.Run("empty code passes", func(t *testing.T) {
		assert.NoError(t, ValidateJSCodeSecurity(""))
	})

	t.Run("__proto__ blocked", func(t *testing.T) {
		code := `var x = {}; x.__proto__.polluted = true;`
		err := ValidateJSCodeSecurity(code)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dangerous pattern")
	})

	t.Run("constructor.constructor blocked", func(t *testing.T) {
		code := `"".constructor.constructor("return this")()`
		err := ValidateJSCodeSecurity(code)
		assert.Error(t, err)
	})

	t.Run("Function() blocked", func(t *testing.T) {
		code := `new Function("return process")()`
		err := ValidateJSCodeSecurity(code)
		assert.Error(t, err)
	})

	t.Run("import() blocked", func(t *testing.T) {
		code := `import("fs").then(m => m.readFileSync("/etc/passwd"))`
		err := ValidateJSCodeSecurity(code)
		assert.Error(t, err)
	})

	t.Run("child_process blocked", func(t *testing.T) {
		code := `require("child_process").execSync("whoami")`
		err := ValidateJSCodeSecurity(code)
		assert.Error(t, err)
	})

	t.Run("Object.defineProperty blocked", func(t *testing.T) {
		code := `Object.defineProperty(x, "y", {get: evil})`
		err := ValidateJSCodeSecurity(code)
		assert.Error(t, err)
	})

	t.Run("Object.getPrototypeOf blocked", func(t *testing.T) {
		code := `Object.getPrototypeOf(x)`
		err := ValidateJSCodeSecurity(code)
		assert.Error(t, err)
	})

	t.Run("Object.setPrototypeOf blocked", func(t *testing.T) {
		code := `Object.setPrototypeOf(x, null)`
		err := ValidateJSCodeSecurity(code)
		assert.Error(t, err)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// NormalizeSignerDisplayName
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeSignerDisplayName(t *testing.T) {
	t.Run("normal name", func(t *testing.T) {
		assert.Equal(t, "My Signer", NormalizeSignerDisplayName("My Signer"))
	})

	t.Run("trims whitespace", func(t *testing.T) {
		assert.Equal(t, "My Signer", NormalizeSignerDisplayName("  My Signer  "))
	})

	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", NormalizeSignerDisplayName(""))
	})

	t.Run("whitespace only", func(t *testing.T) {
		assert.Equal(t, "", NormalizeSignerDisplayName("   "))
	})

	t.Run("truncates long name", func(t *testing.T) {
		long := strings.Repeat("a", 300)
		result := NormalizeSignerDisplayName(long)
		assert.Equal(t, 256, len(result))
	})

	t.Run("exact max length", func(t *testing.T) {
		exact := strings.Repeat("b", 256)
		assert.Equal(t, exact, NormalizeSignerDisplayName(exact))
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// NormalizeSignerTags
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeSignerTags(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result, err := NormalizeSignerTags(nil)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("normal tags", func(t *testing.T) {
		result, err := NormalizeSignerTags([]string{"hot", "production"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"hot", "production"}, result)
	})

	t.Run("deduplicates case-insensitive", func(t *testing.T) {
		result, err := NormalizeSignerTags([]string{"Hot", "hot", "HOT"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"Hot"}, result)
	})

	t.Run("trims whitespace", func(t *testing.T) {
		result, err := NormalizeSignerTags([]string{"  hot  ", "  cold  "})
		assert.NoError(t, err)
		assert.Equal(t, []string{"hot", "cold"}, result)
	})

	t.Run("skips empty tags", func(t *testing.T) {
		result, err := NormalizeSignerTags([]string{"hot", "", "  ", "cold"})
		assert.NoError(t, err)
		assert.Equal(t, []string{"hot", "cold"}, result)
	})

	t.Run("tag too long", func(t *testing.T) {
		long := strings.Repeat("x", 65)
		_, err := NormalizeSignerTags([]string{long})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "longer than")
	})

	t.Run("too many tags", func(t *testing.T) {
		tags := make([]string, 34)
		for i := range tags {
			tags[i] = strings.Repeat("a", 1) + string(rune('a'+i%26)) + string(rune('0'+i/26))
		}
		_, err := NormalizeSignerTags(tags)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at most")
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// SignerHasTag
// ─────────────────────────────────────────────────────────────────────────────

func TestSignerHasTag(t *testing.T) {
	tags := []string{"hot", "production", "Treasury"}

	assert.True(t, SignerHasTag(tags, "hot"))
	assert.True(t, SignerHasTag(tags, "HOT"))
	assert.True(t, SignerHasTag(tags, "treasury"))
	assert.True(t, SignerHasTag(tags, "  hot  "))
	assert.True(t, SignerHasTag(tags, "")) // empty query returns true
	assert.False(t, SignerHasTag(tags, "cold"))
	assert.False(t, SignerHasTag(nil, "hot"))
}
