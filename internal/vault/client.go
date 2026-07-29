package vault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
)

var (
	ErrUnavailable         = errors.New("vault unavailable")
	errAppRoleLoginBlocked = errors.New("approle login blocked; restart required")
)

const (
	defaultRenewalDelay = time.Minute
	minimumRenewalRetry = 100 * time.Millisecond
	maximumRenewalRetry = time.Minute
)

type Client struct {
	address      string
	namespace    string
	auth         config.VaultAuthConfig
	kvMount      string
	tokenRenewal bool
	httpClient   *http.Client

	// authMu serializes AppRole token replacement across request and renewal paths.
	authMu sync.Mutex
	// renewMu protects the renewal worker lifecycle fields.
	renewMu sync.Mutex
	// mu protects the active token and all metadata derived from its lease.
	mu            sync.RWMutex
	token         string
	renewable     bool
	leaseDuration time.Duration
	leaseExpires  time.Time
	// appRoleLoginBlocked prevents credential churn after Vault accepts a login
	// whose response or issued token cannot be safely admitted. Correcting the
	// upstream condition requires restart.
	appRoleLoginBlocked bool
	cancelRenew         context.CancelFunc
	renewDone           chan struct{}
	tokenChanged        chan struct{}
}

func New(cfg config.VaultConfig) (*Client, error) {
	if cfg.RequestTimeout.Duration == 0 {
		cfg.RequestTimeout.Duration = 5 * time.Second
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Client{
		address:      strings.TrimRight(cfg.Address, "/"),
		namespace:    cfg.Namespace,
		auth:         cfg.Auth,
		kvMount:      strings.Trim(cfg.KV.Mount, "/"),
		tokenRenewal: cfg.TokenRenewal,
		httpClient: &http.Client{
			Timeout: cfg.RequestTimeout.Duration,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		tokenChanged: make(chan struct{}, 1),
	}, nil
}

func (c *Client) Ready(ctx context.Context) error {
	if c.auth.Method == "approle" && c.isAppRoleLoginBlocked() {
		return fmt.Errorf("%w: %w", ErrUnavailable, errAppRoleLoginBlocked)
	}
	if err := c.Health(ctx); err != nil {
		return err
	}
	if c.currentToken() == "" {
		var err error
		if c.auth.Method == "approle" {
			err = c.reauthenticateAppRole(ctx, "")
		} else {
			err = c.Authenticate(ctx)
		}
		if err != nil {
			return fmt.Errorf("auth failed: %w", err)
		}
		// Authenticate verifies token usability and unlimited-use semantics.
		return nil
	}
	return c.lookupSelf(ctx, true)
}

func (c *Client) Health(ctx context.Context) error {
	endpoint, err := c.apiURLWithQuery("sys/health", url.Values{
		"perfstandbyok": {"true"},
		"standbyok":     {"true"},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	// Vault restricts sys/health to the root namespace. Authentication, token,
	// and KV operations remain scoped to the configured tenant namespace.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: health check failed", ErrUnavailable)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: health check failed", ErrUnavailable)
	}
	return nil
}

func (c *Client) ReadKV(ctx context.Context, logicalPath string) (map[string]any, error) {
	return c.readKV(ctx, logicalPath, true)
}

func (c *Client) readKV(ctx context.Context, logicalPath string, retryAuth bool) (map[string]any, error) {
	apiPath, err := KV2DataPath(c.kvMount, logicalPath)
	if err != nil {
		return nil, err
	}
	endpoint, err := c.apiURL(apiPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	usedToken := c.currentToken()
	c.addHeadersWithToken(req, usedToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: read failed", ErrUnavailable)
	}
	if retryAuth && c.auth.Method == "approle" && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		status := resp.StatusCode
		drainClose(resp.Body)
		shouldReauthenticate := status == http.StatusUnauthorized
		if status == http.StatusForbidden {
			valid, err := c.tokenValid(ctx, usedToken)
			if err != nil {
				return nil, err
			}
			shouldReauthenticate = !valid
		}
		if !shouldReauthenticate {
			return nil, fmt.Errorf("%w: read failed", ErrUnavailable)
		}
		if err := c.reauthenticateAppRole(ctx, usedToken); err != nil {
			return nil, fmt.Errorf("auth failed: %w", err)
		}
		return c.readKV(ctx, logicalPath, false)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%w: read failed", ErrUnavailable)
	}
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := decodeJSONResponse(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("%w: invalid response", ErrUnavailable)
	}
	if out.Data.Data == nil {
		return nil, fmt.Errorf("%w: invalid kv v2 response", ErrUnavailable)
	}
	return out.Data.Data, nil
}

func (c *Client) addHeaders(req *http.Request) {
	c.addHeadersWithToken(req, c.currentToken())
}

func (c *Client) addHeadersWithToken(req *http.Request, token string) {
	c.addNamespace(req)
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
}

func (c *Client) addNamespace(req *http.Request) {
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
}

func (c *Client) currentToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

func (c *Client) isRenewable() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.renewable
}

func (c *Client) renewSleep() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.leaseDuration > 0 {
		return c.leaseDuration / 2
	}
	return defaultRenewalDelay
}

func (c *Client) renewRetrySleep() time.Duration {
	c.mu.RLock()
	expires := c.leaseExpires
	c.mu.RUnlock()
	if expires.IsZero() {
		return maximumRenewalRetry
	}
	remaining := time.Until(expires)
	if remaining <= 0 {
		return maximumRenewalRetry
	}
	delay := remaining / 2
	if delay <= 0 {
		return remaining
	}
	if delay < minimumRenewalRetry && remaining > minimumRenewalRetry {
		return minimumRenewalRetry
	}
	if delay > maximumRenewalRetry {
		return maximumRenewalRetry
	}
	return delay
}

func (c *Client) isAppRoleLoginBlocked() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.appRoleLoginBlocked
}

func (c *Client) blockAppRoleLogin() {
	c.mu.Lock()
	c.appRoleLoginBlocked = true
	c.mu.Unlock()
}

func (c *Client) setToken(token string, renewable bool, leaseDuration time.Duration) {
	c.mu.Lock()
	c.token = token
	c.renewable = renewable
	c.leaseDuration = leaseDuration
	c.leaseExpires = time.Time{}
	if leaseDuration > 0 {
		c.leaseExpires = time.Now().Add(leaseDuration)
	}
	c.mu.Unlock()
	select {
	case c.tokenChanged <- struct{}{}:
	default:
	}
}

func drainClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}
