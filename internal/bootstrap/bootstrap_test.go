package bootstrap

import (
	"errors"
	"testing"
)

func TestErrAdminAlreadyExists(t *testing.T) {
	if !errors.Is(ErrAdminAlreadyExists, ErrAdminAlreadyExists) {
		t.Error("ErrAdminAlreadyExists should be self-comparable")
	}
	if ErrAdminAlreadyExists.Error() == "" {
		t.Error("error message should not be empty")
	}
}

func TestAdminResultFields(t *testing.T) {
	r := AdminResult{
		KeystorePath: "/tmp/keystore.json",
		PubKeyPath:   "/tmp/pubkey.pem",
		PubKeyHex:    "abcd1234",
		KeystoreJSON: `{"crypto":{}}`,
	}
	if r.KeystorePath != "/tmp/keystore.json" {
		t.Errorf("unexpected KeystorePath: %s", r.KeystorePath)
	}
	if r.PubKeyHex != "abcd1234" {
		t.Errorf("unexpected PubKeyHex: %s", r.PubKeyHex)
	}
}
