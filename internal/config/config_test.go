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
	"time"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/signature"
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
    repo: "example/repo"
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

func TestConfigRejectsAmbiguousOrUnboundedInputs(t *testing.T) {
	t.Run("multiple YAML documents", func(t *testing.T) {
		if _, err := LoadBytes([]byte("{}\n---\n{}\n")); err == nil {
			t.Fatal("expected multiple documents to be rejected")
		}
	})

	for _, tt := range []struct {
		name     string
		timeouts string
	}{
		{name: "negative read timeout", timeouts: "server:\n  read_timeout: \"-1s\""},
		{name: "negative write timeout", timeouts: "server:\n  write_timeout: \"-1s\""},
		{name: "negative idle timeout", timeouts: "server:\n  idle_timeout: \"-1s\""},
		{name: "negative vault timeout", timeouts: "vault_timeout: true"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.timeouts
			vaultTimeout := ""
			if tt.timeouts == "vault_timeout: true" {
				server = ""
				vaultTimeout = "  request_timeout: \"-1s\"\n"
			}
			yaml := server + `
woodpecker:
  public_key: "test-key"
vault:
  address: "http://vault.example"
` + vaultTimeout + `  auth:
    method: "token"
    token: "token"
rules: []
`
			if _, err := LoadBytes([]byte(yaml)); err == nil {
				t.Fatal("expected non-positive timeout to be rejected")
			}
		})
	}

	t.Run("duplicate secret in one rule", func(t *testing.T) {
		_, err := LoadBytes([]byte(`
woodpecker:
  public_key: "test-key"
vault:
  address: "http://vault.example"
  auth:
    method: "token"
    token: "token"
rules:
  - id: "main"
    repo: "example/repo"
    allow_override: true
    secrets:
      - name: "TOKEN"
        path: "one"
        field: "value"
      - name: "TOKEN"
        path: "two"
        field: "value"
`))
		if err == nil {
			t.Fatal("expected duplicate secret in one rule to be rejected")
		}
	})

	t.Run("blank rule event", func(t *testing.T) {
		_, err := LoadBytes([]byte(`
woodpecker:
  public_key: "test-key"
vault:
  address: "http://vault.example"
  auth:
    method: "token"
    token: "token"
rules:
  - id: "main"
    repo: "example/repo"
    events: [""]
    secrets:
      - name: "TOKEN"
        path: "one"
        field: "value"
`))
		if err == nil {
			t.Fatal("expected blank event to be rejected")
		}
	})

	for _, path := range []string{"secret/", "team//secret", "team/./secret", "team/."} {
		t.Run("non-canonical logical path "+path, func(t *testing.T) {
			if err := ValidateLogicalPath(path); err == nil {
				t.Fatalf("expected %q to be rejected", path)
			}
		})
	}
	if err := ValidateLogicalPath("application/data/signing-key"); err != nil {
		t.Fatalf("nested data segment should be a valid logical path: %v", err)
	}

	for _, tt := range []struct {
		name string
		rule RuleConfig
	}{
		{name: "empty ref pattern", rule: RuleConfig{Refs: []string{""}}},
		{name: "whitespace ref pattern", rule: RuleConfig{Refs: []string{" refs/heads/main"}}},
		{name: "empty tag pattern", rule: RuleConfig{Tags: []string{""}}},
		{name: "whitespace tag pattern", rule: RuleConfig{Tags: []string{"v* "}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.rule.ID = "rule"
			tt.rule.Repo = "example/repo"
			tt.rule.Secrets = []SecretConfig{{Name: "TOKEN", Path: "secret", Field: "value"}}
			if err := tt.rule.Validate(0); err == nil {
				t.Fatal("expected empty or non-canonical selector to be rejected")
			}
		})
	}
}

func TestVaultConfigRejectsUnsafeEndpointsAndMounts(t *testing.T) {
	base := VaultConfig{
		Address:        "https://vault.example.com",
		Auth:           VaultAuthConfig{Method: "token", Token: "token"},
		KV:             VaultKVConfig{Version: 2, Mount: "kv"},
		RequestTimeout: Duration{Duration: time.Second},
	}
	for _, tt := range []struct {
		name   string
		mutate func(*VaultConfig)
	}{
		{name: "non HTTP address", mutate: func(v *VaultConfig) { v.Address = "file:///tmp/vault" }},
		{name: "address user info", mutate: func(v *VaultConfig) { v.Address = "https://token@vault.example.com" }},
		{name: "address query", mutate: func(v *VaultConfig) { v.Address = "https://vault.example.com?target=other" }},
		{name: "KV parent mount", mutate: func(v *VaultConfig) { v.KV.Mount = ".." }},
		{name: "empty KV mount segment", mutate: func(v *VaultConfig) { v.KV.Mount = "team//kv" }},
		{name: "token renewal with token auth", mutate: func(v *VaultConfig) { v.TokenRenewal = true }},
		{name: "inline token surrounding whitespace", mutate: func(v *VaultConfig) { v.Auth.Token = " token\n" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected unsafe Vault configuration to be rejected")
			}
		})
	}

	approle := base
	approle.Auth = VaultAuthConfig{Method: "approle", MountPath: "../approle", RoleID: "role", SecretID: "secret"}
	if err := approle.Validate(); err == nil {
		t.Fatal("expected unsafe AppRole mount to be rejected")
	}

	for _, tt := range []struct {
		name   string
		mutate func(*VaultConfig)
	}{
		{name: "inline role ID surrounding whitespace", mutate: func(v *VaultConfig) { v.Auth.RoleID = " role" }},
		{name: "inline secret ID surrounding whitespace", mutate: func(v *VaultConfig) { v.Auth.SecretID = "secret " }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.Auth = VaultAuthConfig{Method: "approle", MountPath: "approle", RoleID: "role", SecretID: "secret"}
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected inline AppRole credential whitespace to be rejected")
			}
		})
	}
}

func TestReadConfiguredSecretWhitespaceHandling(t *testing.T) {
	if _, err := ReadConfiguredSecret(" token\n", "", "vault token"); err == nil {
		t.Fatal("expected inline credential whitespace to be rejected")
	}

	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConfiguredSecret("", path, "vault token")
	if err != nil {
		t.Fatalf("ReadConfiguredSecret: %v", err)
	}
	if got != "token" {
		t.Fatalf("got %q, want trimmed file credential", got)
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
