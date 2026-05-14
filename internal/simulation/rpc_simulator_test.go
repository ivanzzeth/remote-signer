package simulation

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestRPCSimulator_ResponseSizeLimit verifies that oversized RPC responses
// are rejected because the truncated body cannot be parsed as valid JSON.
func TestRPCSimulator_ResponseSizeLimit(t *testing.T) {
	// Serve a response larger than 1MB.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write a valid-looking JSON prefix, then pad to exceed 1MB.
		prefix := `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]}]}],"padding":"`
		w.Write([]byte(prefix))
		// Write padding to exceed 1MB limit.
		padding := strings.Repeat("A", 2*1024*1024)
		w.Write([]byte(padding))
		w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000, // 5s
	}, testLogger())
	if err != nil {
		t.Fatalf("NewRPCSimulator: %v", err)
	}

	_, err = sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})

	// The response should fail to unmarshal because it was truncated at 1MB.
	if err == nil {
		t.Fatal("expected error due to oversized response being truncated, got nil")
	}
	// Accept either unmarshal error (truncated JSON) or other parse failure.
	if !strings.Contains(err.Error(), "unmarshal") && !strings.Contains(err.Error(), "unexpected") {
		t.Logf("error (acceptable): %v", err)
	}
}

// TestRPCSimulator_NormalResponseSucceeds verifies that a normal-sized
// response is processed correctly (not affected by the LimitReader).
func TestRPCSimulator_NormalResponseSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"calls":[{"status":"0x1","gasUsed":"0x5208","returnData":"0x","logs":[]}]}]}`)
	}))
	defer srv.Close()

	sim, err := NewRPCSimulator(RPCSimulatorConfig{
		RPCGatewayURL: srv.URL,
		Timeout:       5000000000,
	}, testLogger())
	if err != nil {
		t.Fatalf("NewRPCSimulator: %v", err)
	}

	result, err := sim.Simulate(context.Background(), &SimulationRequest{
		ChainID: "1",
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x0",
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if !result.Success {
		t.Error("expected simulation success")
	}
}
