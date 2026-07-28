package httpserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/signature"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/vault"
	"github.com/yaronf/httpsign"
)

func TestSecretsEndpoint(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(priv.Public().(ed25519.PublicKey), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{
		data: map[string]map[string]any{
			"cicd/woodpecker/deploy": {
				"vault_addr":      "https://vault.example.com",
				"vault_app_role":  "role",
				"vault_secret_id": "secret",
			},
		},
	}
	srv := New(testServerConfig(), []config.RuleConfig{
		{
			ID:       "main",
			Repo:     "sendico/sendico",
			Events:   []string{"push"},
			Branches: []string{"main"},
			Secrets: []config.SecretConfig{
				{Name: "VAULT_ADDR", Path: "cicd/woodpecker/deploy", Field: "vault_addr", Events: []string{"push"}, Images: []string{"woodpeckerci/plugin-docker-buildx"}},
				{Name: "VAULT_APP_ROLE", Path: "cicd/woodpecker/deploy", Field: "vault_app_role"},
				{Name: "VAULT_SECRET_ID", Path: "cicd/woodpecker/deploy", Field: "vault_secret_id"},
			},
		},
	}, verifier, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	body := []byte(`{"repo":{"namespace":"sendico","name":"sendico"},"pipeline":{"event":"push","branch":"main","ref":"refs/heads/main","refspec":""}}`)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, signedRequest(t, priv, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if store.reads["cicd/woodpecker/deploy"] != 1 {
		t.Fatalf("expected one vault read, got %#v", store.reads)
	}
	wantPrefix := `{"secrets":[{"name":"VAULT_ADDR","value":"https://vault.example.com","events":["push"],"images":["woodpeckerci/plugin-docker-buildx"]},{"name":"VAULT_APP_ROLE","value":"role"},{"name":"VAULT_SECRET_ID","value":"secret"}]}`
	if strings.TrimSpace(rec.Body.String()) != wantPrefix {
		t.Fatalf("unexpected body:\n%s", rec.Body.String())
	}
}

func TestSecretsEndpointFailures(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(priv.Public().(ed25519.PublicKey), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	baseRules := []config.RuleConfig{{
		ID:       "main",
		Repo:     "sendico/sendico",
		Events:   []string{"push"},
		Branches: []string{"main"},
		Secrets:  []config.SecretConfig{{Name: "VAULT_ADDR", Path: "p", Field: "vault_addr"}},
	}}
	body := []byte(`{"repo":{"namespace":"sendico","name":"sendico"},"pipeline":{"event":"push","branch":"main","ref":"refs/heads/main"}}`)
	tests := []struct {
		name        string
		store       *fakeStore
		rules       []config.RuleConfig
		req         *http.Request
		want        int
		wantNoVault bool
	}{
		{
			name:        "missing signature",
			store:       &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules:       baseRules,
			req:         httptest.NewRequest(http.MethodPost, "http://example.test/secrets", bytes.NewReader(body)),
			want:        http.StatusUnauthorized,
			wantNoVault: true,
		},
		{
			name:        "upstream advisory signature input",
			store:       &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules:       baseRules,
			req:         advisorySignatureRequest(t, body),
			want:        http.StatusUnauthorized,
			wantNoVault: true,
		},
		{
			name:  "wrong public key",
			store: &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules: baseRules,
			req: func() *http.Request {
				_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return signedRequest(t, otherPriv, body)
			}(),
			want:        http.StatusUnauthorized,
			wantNoVault: true,
		},
		{
			name:  "tampered body",
			store: &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules: baseRules,
			req: func() *http.Request {
				req := signedRequest(t, priv, body)
				req.Body = io.NopCloser(strings.NewReader(`{"repo":{},"pipeline":{}}`))
				return req
			}(),
			want:        http.StatusUnauthorized,
			wantNoVault: true,
		},
		{
			name:  "no match",
			store: &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules: baseRules,
			req:   signedRequest(t, priv, []byte(`{"repo":{"namespace":"other","name":"repo"},"pipeline":{"event":"push","branch":"main","ref":"refs/heads/main"}}`)),
			want:  http.StatusNoContent,
		},
		{
			name:        "inconsistent event and ref",
			store:       &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules:       baseRules,
			req:         signedRequest(t, priv, []byte(`{"repo":{"namespace":"sendico","name":"sendico"},"pipeline":{"event":"push","branch":"main","ref":"refs/tags/v1.2.3"}}`)),
			want:        http.StatusNoContent,
			wantNoVault: true,
		},
		{
			name:        "inconsistent push branch and ref",
			store:       &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules:       baseRules,
			req:         signedRequest(t, priv, []byte(`{"repo":{"namespace":"sendico","name":"sendico"},"pipeline":{"event":"push","branch":"main","ref":"refs/heads/feature"}}`)),
			want:        http.StatusNoContent,
			wantNoVault: true,
		},
		{
			name:  "contradictory fork signals",
			store: &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules: []config.RuleConfig{{
				ID:                "pull-request",
				Repo:              "sendico/sendico",
				Events:            []string{"pull_request"},
				AllowPullRequests: true,
				Secrets:           []config.SecretConfig{{Name: "VAULT_ADDR", Path: "p", Field: "vault_addr"}},
			}},
			req:         signedRequest(t, priv, []byte(`{"repo":{"namespace":"sendico","name":"sendico","fork":true},"pipeline":{"event":"pull_request","branch":"feature","ref":"refs/pull/1/head","from_fork":false}}`)),
			want:        http.StatusNoContent,
			wantNoVault: true,
		},
		{
			name:  "malformed json after valid signature",
			store: &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": "x"}}},
			rules: baseRules,
			req:   signedRequest(t, priv, []byte(`{`)),
			want:  http.StatusBadRequest,
		},
		{
			name:  "vault unavailable",
			store: &fakeStore{err: vault.ErrUnavailable},
			rules: baseRules,
			req:   signedRequest(t, priv, body),
			want:  http.StatusServiceUnavailable,
		},
		{
			name:  "missing field",
			store: &fakeStore{data: map[string]map[string]any{"p": {"other": "x"}}},
			rules: baseRules,
			req:   signedRequest(t, priv, body),
			want:  http.StatusInternalServerError,
		},
		{
			name:  "non string field",
			store: &fakeStore{data: map[string]map[string]any{"p": {"vault_addr": 123}}},
			rules: baseRules,
			req:   signedRequest(t, priv, body),
			want:  http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := New(testServerConfig(), tt.rules, verifier, tt.store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, tt.req)
			if rec.Code != tt.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tt.want, rec.Body.String())
			}
			if tt.wantNoVault && tt.store.totalReads() != 0 {
				t.Fatalf("vault was contacted before signature verification: %#v", tt.store.reads)
			}
		})
	}
}

func TestWrongMethodAndProbes(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(priv.Public().(ed25519.PublicKey), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{data: map[string]map[string]any{}}
	handler := New(testServerConfig(), nil, verifier, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/secrets", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/healthz", nil))
	if rec.Code != http.StatusOK || store.readyCalls != 0 {
		t.Fatalf("healthz status=%d readyCalls=%d", rec.Code, store.readyCalls)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/readyz", nil))
	if rec.Code != http.StatusOK || store.readyCalls != 1 {
		t.Fatalf("readyz status=%d readyCalls=%d", rec.Code, store.readyCalls)
	}
	store.readyErr = vault.ErrUnavailable
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://example.test/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz unavailable status=%d", rec.Code)
	}
}

func TestSignedRequestWithFakeVaultClient(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(priv.Public().(ed25519.PublicKey), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	fv := newHTTPFakeVault()
	defer fv.server.Close()
	client, err := vault.New(config.VaultConfig{
		Address: fv.server.URL,
		Auth:    config.VaultAuthConfig{Method: "token", Token: "good-token"},
		KV:      config.VaultKVConfig{Version: 2, Mount: "kv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler := New(testServerConfig(), []config.RuleConfig{{
		ID:       "main",
		Repo:     "sendico/sendico",
		Events:   []string{"push"},
		Branches: []string{"main"},
		Secrets:  []config.SecretConfig{{Name: "VAULT_ADDR", Path: "cicd/woodpecker/deploy", Field: "vault_addr"}},
	}}, verifier, client, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	body := []byte(`{"repo":{"namespace":"sendico","name":"sendico"},"pipeline":{"event":"push","branch":"main","ref":"refs/heads/main"}}`)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, signedRequest(t, priv, body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fv.reads != 1 {
		t.Fatalf("expected one fake Vault read, got %d", fv.reads)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://example.test/secrets", bytes.NewReader(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fv.reads != 1 {
		t.Fatalf("fake Vault was contacted for unsigned request")
	}
}

func signedRequest(t *testing.T, priv ed25519.PrivateKey, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://example.test/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	digestBody := io.NopCloser(bytes.NewReader(body))
	digest, err := httpsign.GenerateContentDigestHeader(&digestBody, []string{httpsign.DigestSha256})
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Digest", digest)
	signer, err := httpsign.NewEd25519Signer(priv, httpsign.NewSignConfig(), httpsign.Headers("@request-target", "content-digest"))
	if err != nil {
		t.Fatal(err)
	}
	sigInput, sig, err := httpsign.SignRequest(signature.SignatureName, *signer, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", sig)
	req.Body = io.NopCloser(bytes.NewReader(body))
	return req
}

func advisorySignatureRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://example.test/secrets", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	digestBody := io.NopCloser(bytes.NewReader(body))
	digest, err := httpsign.GenerateContentDigestHeader(&digestBody, []string{httpsign.DigestSha256})
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Signature-Input", fmt.Sprintf(
		`%s=("@request-target" "content-digest" "x";req=1);created=%d;alg="ed25519"`,
		signature.SignatureName,
		time.Now().Unix(),
	))
	req.Header.Set("Signature", signature.SignatureName+"=:QUFBQQ==:")
	return req
}

func testServerConfig() config.ServerConfig {
	return config.ServerConfig{
		ReadTimeout:  config.Duration{Duration: time.Second},
		MaxBodyBytes: 1 << 20,
	}
}

type fakeStore struct {
	data       map[string]map[string]any
	err        error
	readyErr   error
	readyCalls int
	reads      map[string]int
}

type httpFakeVault struct {
	server *httptest.Server
	reads  int
}

func newHTTPFakeVault() *httpFakeVault {
	fv := &httpFakeVault{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/kv/data/cicd/woodpecker/deploy", func(w http.ResponseWriter, r *http.Request) {
		fv.reads++
		if r.Header.Get("X-Vault-Token") != "good-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{"vault_addr": "https://vault.example.com"},
			},
		})
	})
	fv.server = httptest.NewServer(mux)
	return fv
}

func (f *fakeStore) Ready(context.Context) error {
	f.readyCalls++
	return f.readyErr
}

func (f *fakeStore) ReadKV(_ context.Context, path string) (map[string]any, error) {
	if f.reads == nil {
		f.reads = map[string]int{}
	}
	f.reads[path]++
	if f.err != nil {
		return nil, f.err
	}
	data, ok := f.data[path]
	if !ok {
		return nil, vault.ErrUnavailable
	}
	return data, nil
}

func (f *fakeStore) totalReads() int {
	total := 0
	for _, count := range f.reads {
		total += count
	}
	return total
}
