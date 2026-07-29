package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestRunBindsBeforeAppRoleAuthentication(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	var vaultRequests atomic.Int64
	vaultServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		vaultRequests.Add(1)
	}))
	defer vaultServer.Close()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.yml")
	configBody := fmt.Sprintf(`
server:
  listen_addr: %q
woodpecker:
  public_key: %q
vault:
  address: %q
  auth:
    method: approle
    role_id: role
    secret_id: secret
rules: []
`, occupied.Addr().String(), base64.StdEncoding.EncodeToString(publicKey), vaultServer.URL)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFIG_FILE", configPath)

	if code := run(); code != 1 {
		t.Fatalf("run exit code = %d, want 1", code)
	}
	if got := vaultRequests.Load(); got != 0 {
		t.Fatalf("Vault requests before listener bind: %d", got)
	}
}
