package httpserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/signature"
)

func TestResolutionDeadlineFailsClosed(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(priv.Public().(ed25519.PublicKey), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{waitForContext: true}
	cfg := testServerConfig()
	cfg.WriteTimeout.Duration = 50 * time.Millisecond
	handler := New(cfg, []config.RuleConfig{{
		ID:       "main",
		Repo:     "example/repo",
		Events:   []string{"push"},
		Branches: []string{"main"},
		Secrets:  []config.SecretConfig{{Name: "TOKEN", Path: "p", Field: "token"}},
	}}, verifier, store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler()

	body := []byte(`{"repo":{"full_name":"example/repo"},"pipeline":{"event":"push","branch":"main","ref":"refs/heads/main"}}`)
	rec := httptest.NewRecorder()
	started := time.Now()
	handler.ServeHTTP(rec, signedRequest(t, priv, body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("aggregate resolution deadline was not enforced: %v", elapsed)
	}
}

func TestResponseWriteFailureIsLogged(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signature.NewVerifier(priv.Public().(ed25519.PublicKey), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{data: map[string]map[string]any{"p": {"token": "secret"}}}
	var logs bytes.Buffer
	handler := New(testServerConfig(), []config.RuleConfig{{
		ID:       "main",
		Repo:     "example/repo",
		Events:   []string{"push"},
		Branches: []string{"main"},
		Secrets:  []config.SecretConfig{{Name: "TOKEN", Path: "p", Field: "token"}},
	}}, verifier, store, slog.New(slog.NewTextHandler(&logs, nil))).Handler()

	body := []byte(`{"repo":{"full_name":"example/repo"},"pipeline":{"event":"push","branch":"main","ref":"refs/heads/main"}}`)
	w := &failingResponseWriter{header: make(http.Header)}
	handler.ServeHTTP(w, signedRequest(t, priv, body))
	if w.status != http.StatusOK {
		t.Fatalf("attempted status=%d", w.status)
	}
	if got := logs.String(); !strings.Contains(got, "response_write_failed") || !strings.Contains(got, "delivery_result=failed") {
		t.Fatalf("delivery failure was not logged accurately: %s", got)
	}
}

type failingResponseWriter struct {
	header http.Header
	status int
}

func (w *failingResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}
