package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// TestParsePrivateKey_EveryFormatAnOperatorHas covers the three shapes a key
// actually arrives in, plus the one that used to be misread.
//
// ⛔ The 64-byte case is the regression. The old implementation took the last
// 32 bytes as the seed — correct for PKCS#8 and for a bare seed, silently wrong
// for a raw 64-byte key, whose last 32 bytes are the public half. It produced a
// different, valid-looking key, and the only symptom was authentication failing
// with an error that said nothing about the key.
func TestParsePrivateKey_EveryFormatAnOperatorHas(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		hexKey string
		b64    string
	}{
		{"hex 32-byte seed", hex.EncodeToString(priv.Seed()), ""},
		{"hex 64-byte key", hex.EncodeToString(priv), ""},
		{"hex with 0x prefix", "0x" + hex.EncodeToString(priv.Seed()), ""},
		{"base64 PKCS#8 DER (a PEM file's body)", "", base64.StdEncoding.EncodeToString(der)},
		{"base64 32-byte seed", "", base64.StdEncoding.EncodeToString(priv.Seed())},
		{"base64 64-byte key", "", base64.StdEncoding.EncodeToString(priv)},
		{"base64 with surrounding whitespace", "", "  " + base64.StdEncoding.EncodeToString(der) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePrivateKey(nil, tc.hexKey, tc.b64)
			if err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !got.Public().(ed25519.PublicKey).Equal(pub) {
				t.Fatal("parsed a different key than the one supplied")
			}
		})
	}
}

// TestParsePrivateKey_RefusesWhatItCannotIdentify: an unidentifiable blob must
// be an error naming what was seen, not a guess. A guess here is a key that
// signs things nobody can verify.
func TestParsePrivateKey_RefusesWhatItCannotIdentify(t *testing.T) {
	for _, tc := range []struct{ name, b64, want string }{
		{"not base64 at all", "!!!not base64!!!", "not valid base64"},
		{"too short", base64.StdEncoding.EncodeToString([]byte("short")), "neither a 32-byte seed"},
		{"48 bytes of noise", base64.StdEncoding.EncodeToString(make([]byte, 48)), "neither a 32-byte seed"},
		{
			"64 bytes whose halves disagree",
			base64.StdEncoding.EncodeToString(make([]byte, 64)),
			"public half does not match its seed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePrivateKey(nil, "", tc.b64)
			if err == nil {
				t.Fatal("want an error, got a key — a guessed key signs things nobody can verify")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should say what was wrong; want it to contain %q, got %v", tc.want, err)
			}
		})
	}
}
