package simulation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSignatureRegistry_SeedAndCache(t *testing.T) {
	reg := NewSignatureRegistry("", time.Hour)
	reg.SeedFunction("0x5bf6f916", "TransactionDeadlinePassed()")

	got := reg.LookupFunctions(context.Background(), "0x5bf6f916")
	if len(got["5bf6f916"]) != 1 {
		t.Fatalf("lookup: %+v", got)
	}
}

func TestSignatureRegistry_EmptyBaseURLSkipsHTTP(t *testing.T) {
	reg := NewSignatureRegistry("", time.Hour)
	got := reg.LookupFunctions(context.Background(), "0xdeadbeef")
	if len(got) != 0 {
		t.Fatalf("expected empty, got %+v", got)
	}
}

func TestSignatureRegistry_HTTPResponse0xKeyed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"result":{"function":{"0x5bf6f916":[{"name":"TransactionDeadlinePassed()"}]},"event":{}}}`))
	}))
	defer srv.Close()

	reg := NewSignatureRegistry(srv.URL, time.Hour)
	got := reg.LookupFunctions(context.Background(), "0x5bf6f916")
	if names := got["5bf6f916"]; len(names) != 1 || names[0] != "TransactionDeadlinePassed()" {
		t.Fatalf("lookup: %+v", got)
	}
}

func TestSignatureRegistry_LiveSourcifyLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("live registry lookup")
	}
	reg := NewSignatureRegistry(defaultRegistryBaseURL, time.Hour)
	got := reg.LookupFunctions(context.Background(), "0x5bf6f916")
	names := got["5bf6f916"]
	if len(names) == 0 {
		t.Fatalf("expected names from live registry, got %+v", got)
	}
	rev := ResolveRevert(context.Background(), reg, "0x5bf6f916")
	if rev.Signature != "TransactionDeadlinePassed()" {
		t.Fatalf("signature=%q reason=%q conf=%q", rev.Signature, rev.Reason, rev.Confidence)
	}
}
