package signature

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestParsePublicKeyAcceptsUnambiguousFormats(t *testing.T) {
	publicKey, pemBytes := testPublicKey(t)
	for name, material := range map[string][]byte{
		"PEM":    pemBytes,
		"base64": []byte(base64.StdEncoding.EncodeToString(publicKey)),
		"raw":    publicKey,
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParsePublicKey(material)
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			if !parsed.Equal(publicKey) {
				t.Fatal("parsed public key differs from input")
			}
		})
	}
}

func TestParsePublicKeyRejectsAmbiguousPEM(t *testing.T) {
	_, pemBytes := testPublicKey(t)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("test public key is not PEM")
	}
	for name, material := range map[string][]byte{
		"two blocks":        append(append([]byte{}, pemBytes...), pemBytes...),
		"leading material":  append([]byte("unexpected\n"), pemBytes...),
		"trailing material": append(append([]byte{}, pemBytes...), []byte("unexpected\n")...),
		"wrong block type":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		"PEM headers": pem.EncodeToMemory(&pem.Block{
			Type:    "PUBLIC KEY",
			Headers: map[string]string{"Comment": "unexpected"},
			Bytes:   block.Bytes,
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKey(material); err == nil {
				t.Fatal("expected ambiguous PEM to be rejected")
			}
		})
	}
}

func testPublicKey(t *testing.T) (ed25519.PublicKey, []byte) {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
