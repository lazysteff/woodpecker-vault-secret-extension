package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
)

func TestVaultPathCharactersRemainLiteral(t *testing.T) {
	tests := []struct {
		logicalPath string
		requestURI  string
	}{
		{logicalPath: "secret?version=1", requestURI: "/v1/kv/data/secret%3Fversion=1"},
		{logicalPath: "secret#fragment", requestURI: "/v1/kv/data/secret%23fragment"},
		{logicalPath: "secret%2Fchild", requestURI: "/v1/kv/data/secret%252Fchild"},
	}
	for _, tt := range tests {
		t.Run(tt.logicalPath, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != tt.requestURI {
					t.Errorf("request URI=%q, want %q", r.RequestURI, tt.requestURI)
				}
				if r.URL.RawQuery != "" {
					t.Errorf("configured path became query %q", r.URL.RawQuery)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"data": map[string]any{"data": map[string]any{"value": "ok"}},
				})
			}))
			defer server.Close()

			client := newTokenClient(t, server.URL)
			data, err := client.ReadKV(context.Background(), tt.logicalPath)
			if err != nil {
				t.Fatalf("ReadKV: %v", err)
			}
			if data["value"] != "ok" {
				t.Fatalf("unexpected data: %#v", data)
			}
		})
	}
}

func TestHealthQueryIsExplicit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/health" {
			t.Errorf("path=%q", r.URL.Path)
		}
		if r.URL.Query().Get("standbyok") != "true" || r.URL.Query().Get("perfstandbyok") != "true" {
			t.Errorf("query=%q", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newTokenClient(t, server.URL)
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

func TestNamespaceIsNotSentToRootHealth(t *testing.T) {
	const namespace = "team/ci"
	var tokenLookups atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/health":
			if got := r.Header.Get("X-Vault-Namespace"); got != "" {
				t.Errorf("health namespace=%q, want root namespace", got)
			}
			w.WriteHeader(http.StatusOK)
		case "/v1/auth/token/lookup-self":
			if got := r.Header.Get("X-Vault-Namespace"); got != namespace {
				t.Errorf("token lookup namespace=%q, want %q", got, namespace)
			}
			tokenLookups.Add(1)
			writeUsableTokenLookup(w)
		case "/v1/kv/data/secret":
			if got := r.Header.Get("X-Vault-Namespace"); got != namespace {
				t.Errorf("KV namespace=%q, want %q", got, namespace)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": map[string]any{"value": "ok"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(config.VaultConfig{
		Address:   server.URL,
		Namespace: namespace,
		Auth:      config.VaultAuthConfig{Method: "token", Token: "token"},
		KV:        config.VaultKVConfig{Version: 2, Mount: "kv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Authenticate(t.Context()); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := client.Health(t.Context()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if _, err := client.ReadKV(t.Context(), "secret"); err != nil {
		t.Fatalf("ReadKV: %v", err)
	}
	if got := tokenLookups.Load(); got != 2 {
		t.Fatalf("token lookups=%d, want 2 admission checks", got)
	}
}

func TestRenewalFallbackAndRequestReauthenticationAreSingleFlight(t *testing.T) {
	var loginCount atomic.Int32
	renewStarted := make(chan struct{})
	releaseRenewal := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, _ *http.Request) {
		close(renewStarted)
		<-releaseRenewal
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
		loginCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "fresh-token", "renewable": true, "lease_duration": 3600},
		})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "fresh-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeUsableTokenLookup(w)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	client.setToken("stale-token", true, 0)
	maintenanceDone := make(chan error, 1)
	go func() {
		renewErr, loginErr := client.maintainAppRoleToken(context.Background())
		if loginErr != nil {
			maintenanceDone <- loginErr
			return
		}
		if renewErr == nil {
			maintenanceDone <- errExpectedRenewalFailure
			return
		}
		maintenanceDone <- nil
	}()
	<-renewStarted

	reauthenticationDone := make(chan error, 1)
	go func() {
		reauthenticationDone <- client.reauthenticateAppRole(context.Background(), "stale-token")
	}()
	close(releaseRenewal)

	if err := <-maintenanceDone; err != nil {
		t.Fatalf("token maintenance: %v", err)
	}
	if err := <-reauthenticationDone; err != nil {
		t.Fatalf("request reauthentication: %v", err)
	}
	if got := loginCount.Load(); got != 1 {
		t.Fatalf("AppRole login count=%d, want 1", got)
	}
	if got := client.currentToken(); got != "fresh-token" {
		t.Fatalf("current token=%q", got)
	}
}

func TestRenewalLoopReschedulesWhenTokenChanges(t *testing.T) {
	renewed := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		if token := r.Header.Get("X-Vault-Token"); token != "short-token" {
			t.Errorf("renewal used token %q, want short-token", token)
		}
		select {
		case renewed <- struct{}{}:
		default:
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "renewed-token", "renewable": true, "lease_duration": 3600},
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
		KV:           config.VaultKVConfig{Version: 2, Mount: "kv"},
		TokenRenewal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.setToken("long-token", true, time.Hour)
	client.StartRenewal(context.Background(), nil)
	defer client.Close()
	client.setToken("short-token", true, 20*time.Millisecond)

	select {
	case <-renewed:
	case <-time.After(time.Second):
		t.Fatal("renewal loop did not reschedule for replacement token lease")
	}
}

func TestRenewalFailureRetriesWithinRemainingLease(t *testing.T) {
	client := newAppRoleClient(t, "http://127.0.0.1")
	client.setToken("token", true, time.Hour)

	normalDelay := client.renewSleep()
	retryDelay := client.renewRetrySleep()
	if retryDelay >= normalDelay {
		t.Fatalf("retry delay=%v must be shorter than normal delay=%v", retryDelay, normalDelay)
	}
	if retryDelay > maximumRenewalRetry {
		t.Fatalf("retry delay=%v exceeds maximum=%v", retryDelay, maximumRenewalRetry)
	}

	expires := time.Now().Add(minimumRenewalRetry / 2)
	client.mu.Lock()
	client.leaseExpires = expires
	client.mu.Unlock()
	remaining := time.Until(expires)
	retryDelay = client.renewRetrySleep()
	if retryDelay <= 0 || retryDelay >= remaining {
		t.Fatalf("short-lease retry delay=%v must remain within lease=%v", retryDelay, remaining)
	}
}

func TestCloseWaitsForRenewalWorker(t *testing.T) {
	requestStarted := make(chan struct{})
	requestStopped := make(chan struct{})
	var startedOnce sync.Once
	var stoppedOnce sync.Once
	transport := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		startedOnce.Do(func() { close(requestStarted) })
		<-r.Context().Done()
		stoppedOnce.Do(func() { close(requestStopped) })
		return nil, r.Context().Err()
	})

	client, err := New(config.VaultConfig{
		Address: "http://127.0.0.1",
		Auth: config.VaultAuthConfig{
			Method:    "approle",
			MountPath: "approle",
			RoleID:    "role",
			SecretID:  "secret",
		},
		KV:           config.VaultKVConfig{Version: 2, Mount: "kv"},
		TokenRenewal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.httpClient.Transport = transport
	client.setToken("token", true, 10*time.Millisecond)
	client.StartRenewal(context.Background(), nil)

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("renewal request did not start")
	}
	client.Close()
	select {
	case <-requestStopped:
	default:
		t.Fatal("Close returned before the renewal request stopped")
	}
	client.renewMu.Lock()
	defer client.renewMu.Unlock()
	if client.cancelRenew != nil || client.renewDone != nil {
		t.Fatal("Close did not clear renewal lifecycle state")
	}
}

func TestAuthResponseTokenStateValidation(t *testing.T) {
	valid := func() authResponse {
		var response authResponse
		response.Auth.ClientToken = "token"
		response.Auth.Renewable = true
		response.Auth.LeaseDuration = 3600
		return response
	}
	tests := []struct {
		name     string
		response authResponse
		wantErr  bool
	}{
		{name: "valid", response: valid()},
		{name: "missing token", response: func() authResponse {
			response := valid()
			response.Auth.ClientToken = ""
			return response
		}(), wantErr: true},
		{name: "token with surrounding whitespace", response: func() authResponse {
			response := valid()
			response.Auth.ClientToken = " token "
			return response
		}(), wantErr: true},
		{name: "zero lease", response: func() authResponse {
			response := valid()
			response.Auth.LeaseDuration = 0
			return response
		}(), wantErr: true},
		{name: "negative lease", response: func() authResponse {
			response := valid()
			response.Auth.LeaseDuration = -1
			return response
		}(), wantErr: true},
		{name: "overflowing lease", response: func() authResponse {
			response := valid()
			response.Auth.LeaseDuration = maxLeaseSeconds + 1
			return response
		}(), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, err := tt.response.tokenState()
			if (err != nil) != tt.wantErr {
				t.Fatalf("tokenState error=%v, wantErr=%v", err, tt.wantErr)
			}
			if !tt.wantErr && (state.token != "token" || state.leaseDuration != time.Hour || !state.renewable) {
				t.Fatalf("unexpected token state: %#v", state)
			}
		})
	}
}

func TestTokenLookupResponseRequiresUnlimitedUses(t *testing.T) {
	zero := int64(0)
	one := int64(1)
	negative := int64(-1)
	for _, tt := range []struct {
		name        string
		numUses     *int64
		wantLimited bool
		wantErr     bool
	}{
		{name: "unlimited", numUses: &zero},
		{name: "limited", numUses: &one, wantLimited: true, wantErr: true},
		{name: "missing", wantErr: true},
		{name: "negative", numUses: &negative, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var response tokenLookupResponse
			response.Data.NumUses = tt.numUses
			err := response.validateUnlimitedUses()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validation error=%v, wantErr=%v", err, tt.wantErr)
			}
			if errors.Is(err, errLimitedUseToken) != tt.wantLimited {
				t.Fatalf("limited-use classification=%v, want %v", errors.Is(err, errLimitedUseToken), tt.wantLimited)
			}
		})
	}
}

func TestAuthenticationRejectsLimitedUseTokens(t *testing.T) {
	var loginCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
		loginCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "limited-token", "renewable": true, "lease_duration": 3600},
		})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"num_uses": 1}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	staticClient, err := New(config.VaultConfig{
		Address: server.URL,
		Auth:    config.VaultAuthConfig{Method: "token", Token: "limited-token"},
		KV:      config.VaultKVConfig{Version: 2, Mount: "kv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := staticClient.Authenticate(context.Background()); !errors.Is(err, errLimitedUseToken) {
		t.Fatalf("static limited-use token error = %v", err)
	}
	if got := staticClient.currentToken(); got != "" {
		t.Fatalf("limited-use static token was installed: %q", got)
	}

	appRoleClient := newAppRoleClient(t, server.URL)
	for range 2 {
		if err := appRoleClient.Authenticate(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("AppRole limited-use token error = %v", err)
		}
	}
	if got := loginCount.Load(); got != 1 {
		t.Fatalf("AppRole login count=%d, want 1 after limited-use token", got)
	}
	if got := appRoleClient.currentToken(); got != "" {
		t.Fatalf("limited-use AppRole token was installed: %q", got)
	}
}

func TestAppRoleAuthenticationRejectsTokenExhaustedByAdmissionCheck(t *testing.T) {
	var lookups atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/token/lookup-self" {
			http.NotFound(w, r)
			return
		}
		if lookups.Add(1) == 1 {
			writeUsableTokenLookup(w)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	state := tokenState{
		token:     "single-use-token",
		renewable: false,
	}

	err := client.installAppRoleToken(t.Context(), state)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("installAppRoleToken() error = %v, want ErrUnavailable", err)
	}
	if got := lookups.Load(); got != 2 {
		t.Fatalf("lookup calls = %d, want 2", got)
	}
	if !client.isAppRoleLoginBlocked() {
		t.Fatal("finite-use AppRole token did not block further login attempts")
	}
	if token := client.currentToken(); token != "" {
		t.Fatalf("installed rejected token %q", token)
	}
}

func TestRenewSelfRejectsIncompleteAuthResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	client.setToken("old-token", true, time.Hour)
	if err := client.renewSelf(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected invalid renewal response to fail closed, got %v", err)
	}
	if got := client.currentToken(); got != "old-token" {
		t.Fatalf("invalid renewal response changed token to %q", got)
	}
}

func TestAppRoleLoginRejectsInvalidLease(t *testing.T) {
	var loginCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		loginCount.Add(1)
		_, _ = io.WriteString(w, `{"auth":{"client_token":"token","renewable":true,"lease_duration":0}}`)
	}))
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	for range 2 {
		if err := client.Authenticate(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected invalid login response to fail closed, got %v", err)
		}
	}
	if got := loginCount.Load(); got != 1 {
		t.Fatalf("AppRole login count=%d, want 1 after invalid successful response", got)
	}
	if !client.isAppRoleLoginBlocked() {
		t.Fatal("invalid successful login response did not block further logins")
	}
	if got := client.currentToken(); got != "" {
		t.Fatalf("invalid login response installed token %q", got)
	}
}

func TestAppRoleWrittenLoginWithLostResponseBlocksFurtherLogins(t *testing.T) {
	var loginCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginCount.Add(1)
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read login request: %v", err)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack login response: %v", err)
			return
		}
		_ = conn.Close()
	}))
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	for range 2 {
		if err := client.Authenticate(t.Context()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected lost login response to fail closed, got %v", err)
		}
	}
	if got := loginCount.Load(); got != 1 {
		t.Fatalf("AppRole login count=%d, want 1 after indeterminate written request", got)
	}
	if !client.isAppRoleLoginBlocked() {
		t.Fatal("lost response for a written login did not block further logins")
	}
}

func TestAppRoleFailureBeforeLoginWriteDoesNotBlockRetry(t *testing.T) {
	client := newAppRoleClient(t, "http://127.0.0.1")
	for range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := client.Authenticate(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected canceled login to fail, got %v", err)
		}
	}
	if client.isAppRoleLoginBlocked() {
		t.Fatal("failure before writing the login request blocked retry")
	}
}

func TestAppRoleAdmissionErrorBlocksFurtherLogins(t *testing.T) {
	var loginCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
		loginCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "candidate-token", "renewable": true, "lease_duration": 3600},
		})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	for range 2 {
		if err := client.Authenticate(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected token admission error to fail closed, got %v", err)
		}
	}
	if got := loginCount.Load(); got != 1 {
		t.Fatalf("AppRole login count=%d, want 1 after candidate admission failure", got)
	}
	if !client.isAppRoleLoginBlocked() {
		t.Fatal("candidate admission error did not block further logins")
	}
	if got := client.currentToken(); got != "" {
		t.Fatalf("failed candidate token was installed: %q", got)
	}
}

func TestAppRoleAdmissionBlockSurvivesSuccessfulRenewal(t *testing.T) {
	var loginCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
		loginCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "old-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "renewed-token", "renewable": true, "lease_duration": 3600},
		})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Vault-Token") {
		case "rejected-token":
			w.WriteHeader(http.StatusInternalServerError)
		case "renewed-token":
			writeUsableTokenLookup(w)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	client.setToken("old-token", true, time.Hour)
	failedCandidate := tokenState{token: "rejected-token", renewable: true, leaseDuration: time.Hour}
	if err := client.installAppRoleToken(t.Context(), failedCandidate); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected candidate admission to fail closed, got %v", err)
	}
	if err := client.renewSelf(t.Context()); err != nil {
		t.Fatalf("renewSelf: %v", err)
	}
	if got := client.currentToken(); got != "renewed-token" {
		t.Fatalf("current token=%q, want renewed-token", got)
	}
	if !client.isAppRoleLoginBlocked() {
		t.Fatal("successful renewal cleared the AppRole login block")
	}
	if err := client.Authenticate(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected AppRole login to remain blocked, got %v", err)
	}
	if got := loginCount.Load(); got != 0 {
		t.Fatalf("AppRole login count=%d, want 0 while blocked", got)
	}
}

func TestReadyReportsPersistentAppRoleLoginBlock(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	client.setToken("usable-token", true, time.Hour)
	client.blockAppRoleLogin()
	err := client.Ready(t.Context())
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, errAppRoleLoginBlocked) {
		t.Fatalf("Ready() error=%v, want unavailable AppRole block", err)
	}
	if got := requestCount.Load(); got != 0 {
		t.Fatalf("blocked readiness made %d Vault requests, want 0", got)
	}
}

func TestBlockedAppRoleLoginUsesDistinctOperationalLog(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	logAppRoleLoginFailure(logger, fmt.Errorf("maintenance: %w", errAppRoleLoginBlocked))

	got := logs.String()
	if !strings.Contains(got, "error_code=vault_auth_blocked") || !strings.Contains(got, "restart required") {
		t.Fatalf("blocked AppRole state was not logged distinctly: %s", got)
	}
}

func TestAppRoleSelfLookupDenialBlocksFurtherLogins(t *testing.T) {
	var loginCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, _ *http.Request) {
		loginCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"auth": map[string]any{"client_token": "uninspectable-token", "renewable": true, "lease_duration": 3600},
		})
	})
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newAppRoleClient(t, server.URL)
	for range 2 {
		if err := client.Authenticate(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected self-lookup denial to fail authentication, got %v", err)
		}
	}
	if got := loginCount.Load(); got != 1 {
		t.Fatalf("AppRole login count=%d, want 1 after capability denial", got)
	}
	if got := client.currentToken(); got != "" {
		t.Fatalf("self-lookup denial installed token %q", got)
	}
}

func TestDecodeJSONResponseIsBoundedAndSingleDocument(t *testing.T) {
	valid := `{"data":{"value":"ok"}}`
	tests := []struct {
		name    string
		payload string
		wantErr bool
	}{
		{name: "valid", payload: valid},
		{name: "second document", payload: valid + `{}`, wantErr: true},
		{name: "trailing garbage", payload: valid + `garbage`, wantErr: true},
		{name: "oversized", payload: valid + strings.Repeat(" ", int(maxResponseBytes)), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out map[string]any
			err := decodeJSONResponse(strings.NewReader(tt.payload), &out)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decode error=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestReadKVRejectsTrailingJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"data":{"value":"ok"}}}{}`)
	}))
	defer server.Close()

	client := newTokenClient(t, server.URL)
	if _, err := client.ReadKV(context.Background(), "secret"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected malformed Vault response to fail closed, got %v", err)
	}
}

var errExpectedRenewalFailure = errors.New("expected renewal failure")

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newTokenClient(t *testing.T, address string) *Client {
	t.Helper()
	client, err := New(config.VaultConfig{
		Address: address,
		Auth:    config.VaultAuthConfig{Method: "token", Token: "token"},
		KV:      config.VaultKVConfig{Version: 2, Mount: "kv"},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.setToken("token", false, 0)
	return client
}

func newAppRoleClient(t *testing.T, address string) *Client {
	t.Helper()
	client, err := New(config.VaultConfig{
		Address: address,
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
	return client
}
