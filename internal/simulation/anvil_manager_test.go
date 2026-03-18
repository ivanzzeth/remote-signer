package simulation

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestManagerStatus_NoInstances verifies that Status returns an empty chains
// map when no anvil instances have been started (no anvil binary required).
func TestManagerStatus_NoInstances(t *testing.T) {
	// We cannot call NewAnvilForkManager without a real anvil binary.
	// Instead, construct the impl directly with minimal fields to test
	// the Status() logic path for zero instances.
	m := &anvilForkManagerImpl{
		cfg: AnvilForkManagerConfig{
			AnvilPath: "/nonexistent/anvil", // version check will fail gracefully
		},
		instances: make(map[string]*anvilInstance),
		stopCh:    make(chan struct{}),
		client:    &http.Client{Timeout: 2 * time.Second},
	}

	ctx := context.Background()
	status := m.Status(ctx)

	if !status.Enabled {
		t.Error("expected Enabled to be true")
	}
	if len(status.Chains) != 0 {
		t.Errorf("expected 0 chains, got %d", len(status.Chains))
	}
	// AnvilVersion should be empty since binary doesn't exist
	// (no error, just empty string — graceful degradation)
}

// TestManagerStatus_WithUnhealthyInstance verifies that Status correctly
// reports an unhealthy instance when the anvil process is not actually running.
func TestManagerStatus_WithUnhealthyInstance(t *testing.T) {
	m := &anvilForkManagerImpl{
		cfg: AnvilForkManagerConfig{
			AnvilPath: "/nonexistent/anvil",
			Timeout:   5 * time.Second,
		},
		instances: map[string]*anvilInstance{
			"1": {
				chainID:      "1",
				port:         19999,
				rpcURL:       "http://127.0.0.1:19999",
				dirty:        true,
				restartCount: 2,
			},
		},
		stopCh: make(chan struct{}),
		client: &http.Client{Timeout: 2 * time.Second},
	}

	ctx := context.Background()
	status := m.Status(ctx)

	if len(status.Chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(status.Chains))
	}

	cs, ok := status.Chains["1"]
	if !ok {
		t.Fatal("expected chain '1' in status")
	}
	if cs.Status != "unhealthy" {
		t.Errorf("expected status 'unhealthy', got %q", cs.Status)
	}
	if cs.Port != 19999 {
		t.Errorf("expected port 19999, got %d", cs.Port)
	}
	if cs.RestartCount != 2 {
		t.Errorf("expected restart_count 2, got %d", cs.RestartCount)
	}
	if !cs.Dirty {
		t.Error("expected dirty to be true")
	}
	if cs.Error == "" {
		t.Error("expected non-empty error for unreachable instance")
	}
}
