package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPrivateKeyFromFile_PathValidation(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	// Write a valid Ed25519 PKCS#8 PEM
	_, priv, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("relative path under cwd works", func(t *testing.T) {
		origWd, _ := os.Getwd()
		defer os.Chdir(origWd)
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		_, err := loadPrivateKeyFromFile("key.pem")
		if err != nil {
			t.Errorf("expected success: %v", err)
		}
	})

	t.Run("path traversal rejected", func(t *testing.T) {
		origWd, _ := os.Getwd()
		defer os.Chdir(origWd)
		if err := os.Chdir(dir); err != nil {
			t.Fatal(err)
		}
		// ".." resolves outside cwd
		_, err := loadPrivateKeyFromFile("..")
		if err == nil {
			t.Error("expected error for path escaping cwd")
		}
		if err != nil && !strings.Contains(err.Error(), "under current directory") {
			t.Errorf("expected 'under current directory' error: %v", err)
		}
	})

	t.Run("absolute path outside cwd rejected", func(t *testing.T) {
		absKeyPath, _ := filepath.Abs(keyPath)
		origWd, _ := os.Getwd()
		defer os.Chdir(origWd)
		// Chdir to a sibling dir so absKeyPath is not under cwd
		parent := filepath.Dir(dir)
		sibling := filepath.Join(parent, "sibling")
		if err := os.MkdirAll(sibling, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(sibling); err != nil {
			t.Fatal(err)
		}
		_, err := loadPrivateKeyFromFile(absKeyPath)
		if err == nil {
			t.Error("expected error for absolute path outside cwd")
		}
		if err != nil && !strings.Contains(err.Error(), "under current directory") {
			t.Errorf("expected 'under current directory' error: %v", err)
		}
	})
}
