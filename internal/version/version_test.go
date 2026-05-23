package version

import "testing"

func TestVersion_Default(t *testing.T) {
	if Version != "dev" {
		t.Errorf("expected default version 'dev', got %q", Version)
	}
}
