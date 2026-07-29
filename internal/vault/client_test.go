package vault

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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
	got, err = KV2DataPath("kv", "application/data/signing-key")
	if err != nil {
		t.Fatal(err)
	}
	if got != "kv/data/application/data/signing-key" {
		t.Fatalf("nested data segment path = %q", got)
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
	_, err = client.ReadKV(context.Background(), "denied")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected unavailable, got %v", err)
	}
	if fake.loginCount != 1 {
		t.Fatalf("policy denial triggered AppRole login: count=%d, want 1", fake.loginCount)
	}
}

func TestAppRoleReauthenticationIsSingleFlight(t *testing.T) {
	const workers = 12
	var staleReads atomic.Int32
	var loginCount atomic.Int32
	releaseStale := make(chan struct{})
	var releaseOnce sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
		loginCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "fresh-token", "renewable": true, "lease_duration": 3600},
		})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "fresh-token" {
			writeUsableTokenLookup(w)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/v1/kv/data/secret", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Vault-Token") {
		case "stale-token":
			if staleReads.Add(1) == workers {
				releaseOnce.Do(func() { close(releaseStale) })
			}
			<-releaseStale
			w.WriteHeader(http.StatusForbidden)
		case "fresh-token":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"value": "ok"}}})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(config.VaultConfig{
		Address: server.URL,
		Auth: config.VaultAuthConfig{
			Method:    "approle",
			MountPath: "approle",
			RoleID:    "role",
			SecretID:  "secret",
		},
		KV: config.VaultKVConfig{Version: 2, Mount: "kv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.setToken("stale-token", true, 0)

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := client.ReadKV(context.Background(), "secret")
			if err == nil && data["value"] != "ok" {
				err = errors.New("unexpected secret value")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := loginCount.Load(); got != 1 {
		t.Fatalf("AppRole login count=%d, want 1", got)
	}
}

func TestVaultClientRefusesRedirects(t *testing.T) {
	var redirectedRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectedRequests.Add(1)
	}))
	defer target.Close()

	t.Run("token read", func(t *testing.T) {
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/capture", http.StatusTemporaryRedirect)
		}))
		defer source.Close()
		client, err := New(config.VaultConfig{
			Address: source.URL,
			Auth:    config.VaultAuthConfig{Method: "token", Token: "vault-token"},
			KV:      config.VaultKVConfig{Version: 2, Mount: "kv"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Authenticate(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected redirected token validation to fail closed, got %v", err)
		}
	})

	t.Run("AppRole login", func(t *testing.T) {
		source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/capture", http.StatusTemporaryRedirect)
		}))
		defer source.Close()
		client, err := New(config.VaultConfig{
			Address: source.URL,
			Auth: config.VaultAuthConfig{
				Method:    "approle",
				MountPath: "approle",
				RoleID:    "role",
				SecretID:  "secret",
			},
			KV: config.VaultKVConfig{Version: 2, Mount: "kv"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Authenticate(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected redirected login to fail closed, got %v", err)
		}
	})

	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("credentials followed redirect %d times", got)
	}
}

func TestAppRoleRenewalUpdatesSharedToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "old-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "renewed-token", "renewable": true, "lease_duration": 7200},
		})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "renewed-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeUsableTokenLookup(w)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := New(config.VaultConfig{
		Address: server.URL,
		Auth: config.VaultAuthConfig{
			Method:    "approle",
			MountPath: "approle",
			RoleID:    "role",
			SecretID:  "secret",
		},
		KV: config.VaultKVConfig{Version: 2, Mount: "kv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.setToken("old-token", true, 0)
	if err := client.renewSelf(context.Background()); err != nil {
		t.Fatalf("renewSelf: %v", err)
	}
	if got := client.currentToken(); got != "renewed-token" {
		t.Fatalf("current token=%q", got)
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
			writeUsableTokenLookup(w)
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
		if token := r.Header.Get("X-Vault-Token"); token != "good-token" && token != "approle-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
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

func writeUsableTokenLookup(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"num_uses": 0}})
}
