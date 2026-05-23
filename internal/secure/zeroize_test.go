package secure

import "testing"

func TestZeroString_Nil(t *testing.T) {
	// Should not panic
	ZeroString(nil)
}

func TestZeroString_Empty(t *testing.T) {
	s := ""
	ZeroString(&s)
	if s != "" {
		t.Errorf("expected empty string, got %q", s)
	}
}

func TestZeroString_NonEmpty(t *testing.T) {
	// Use string([]byte(...)) to force heap allocation — string literals
	// live in read-only memory and would SEGFAULT with unsafe writes.
	s := string([]byte("hello123"))
	ZeroString(&s)
	if s != "" {
		t.Errorf("expected zeroed string, got %q", s)
	}
}
