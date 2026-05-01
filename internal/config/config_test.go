package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/stephan/woodpecker-vault-secret-extension/internal/signature"
)

func TestLoadConfigEnvExpansionAndDefaults(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WOODPECKER_KEY", base64.StdEncoding.EncodeToString(pub))
	t.Setenv("VAULT_TOKEN", "token")
	cfg, err := LoadBytes([]byte(`
woodpecker:
  public_key: "${WOODPECKER_KEY}"
vault:
  address: "http://vault.example"
  auth:
    method: "token"
    token: "${VAULT_TOKEN}"
rules:
  - id: "main"
    repo: "sendico/sendico"
    events: ["push"]
    secrets:
      - name: "VAULT_ADDR"
        path: "cicd/woodpecker/deploy"
        field: "vault_addr"
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.Server.ListenAddr != ":8080" || cfg.Vault.KV.Version != 2 || cfg.Vault.KV.Mount != "kv" {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
	material, err := cfg.Woodpecker.PublicKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signature.ParsePublicKey(material); err != nil {
		t.Fatalf("public key should parse: %v", err)
	}
}

func TestMissingEnvFailsStartup(t *testing.T) {
	_, err := LoadBytes([]byte(`woodpecker: { public_key: "${MISSING_KEY}" }`))
	if err == nil || !strings.Contains(err.Error(), "MISSING_KEY") {
		t.Fatalf("expected missing env error, got %v", err)
	}
}

func TestMissingAndInvalidConfig(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "token")
	_, err := LoadBytes([]byte(`
woodpecker: {}
vault:
  address: "http://vault.example"
  auth:
    method: "token"
    token: "${VAULT_TOKEN}"
rules: []
`))
	if err == nil {
		t.Fatal("expected missing public key error")
	}
	tmp := t.TempDir() + "/key.pem"
	if err := os.WriteFile(tmp, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadBytes([]byte(`
woodpecker:
  public_key_file: "` + tmp + `"
vault:
  address: "http://vault.example"
  auth:
    method: "token"
    token: "${VAULT_TOKEN}"
rules: []
`))
	if err != nil {
		t.Fatalf("LoadBytes should only validate key presence: %v", err)
	}
	material, err := cfg.Woodpecker.PublicKeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signature.ParsePublicKey(material); err == nil {
		t.Fatal("expected invalid public key parse error")
	}
}

func publicKeyPEM(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
