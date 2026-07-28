package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
)

func TestKV2PathValidation(t *testing.T) {
	got, err := KV2DataPath("kv", "cicd/woodpecker/deploy")
	if err != nil {
		t.Fatal(err)
	}
	if got != "kv/data/cicd/woodpecker/deploy" {
		t.Fatalf("got %q", got)
	}
	for _, p := range []string{"", "/secret", "../secret", "a/../secret", "data/secret"} {
		if _, err := KV2DataPath("kv", p); err == nil {
			t.Fatalf("expected invalid path %q", p)
		}
	}
}

func TestTokenAuthReadyAndRead(t *testing.T) {
	fake := newFakeVault(t)
	defer fake.server.Close()
	client, err := New(config.VaultConfig{
		Address: fake.server.URL,
		Auth:    config.VaultAuthConfig{Method: "token", Token: "good-token"},
		KV:      config.VaultKVConfig{Version: 2, Mount: "kv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := client.Ready(context.Background()); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	data, err := client.ReadKV(context.Background(), "cicd/woodpecker/deploy")
	if err != nil {
		t.Fatalf("ReadKV: %v", err)
	}
	if data["vault_addr"] != "https://vault.example.com" {
		t.Fatalf("unexpected data: %#v", data)
	}
}

func TestAppRoleLoginAndReadFailure(t *testing.T) {
	fake := newFakeVault(t)
	defer fake.server.Close()
	client, err := New(config.VaultConfig{
		Address: fake.server.URL,
		Auth: config.VaultAuthConfig{
			Method:    "approle",
			MountPath: "custom-approle",
			RoleID:    "role",
			SecretID:  "secret",
		},
		KV: config.VaultKVConfig{Version: 2, Mount: "kv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if fake.loginCount != 1 {
		t.Fatalf("login count=%d", fake.loginCount)
	}
	_, err = client.ReadKV(context.Background(), "denied")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
}

type fakeVault struct {
	server     *httptest.Server
	loginCount int
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "good-token" || r.Header.Get("X-Vault-Token") == "approle-token" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "ok"}})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/v1/auth/custom-approle/login", func(w http.ResponseWriter, r *http.Request) {
		f.loginCount++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{
				"client_token":   "approle-token",
				"renewable":      true,
				"lease_duration": 3600,
			},
		})
	})
	mux.HandleFunc("/v1/kv/data/cicd/woodpecker/deploy", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"vault_addr": "https://vault.example.com",
				},
			},
		})
	})
	mux.HandleFunc("/v1/kv/data/denied", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	f.server = httptest.NewServer(mux)
	return f
}
