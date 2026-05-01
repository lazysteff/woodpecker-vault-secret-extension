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
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/stephan/woodpecker-vault-secret-extension/internal/config"
)

var ErrUnavailable = errors.New("vault unavailable")

type Client struct {
	address      string
	namespace    string
	auth         config.VaultAuthConfig
	kvMount      string
	timeout      time.Duration
	tokenRenewal bool
	httpClient   *http.Client

	mu            sync.RWMutex
	token         string
	renewable     bool
	leaseDuration time.Duration
	authErr       error
	cancelRenew   context.CancelFunc
}

func New(cfg config.VaultConfig) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Client{
		address:      strings.TrimRight(cfg.Address, "/"),
		namespace:    cfg.Namespace,
		auth:         cfg.Auth,
		kvMount:      strings.Trim(cfg.KV.Mount, "/"),
		timeout:      cfg.RequestTimeout.Duration,
		tokenRenewal: cfg.TokenRenewal,
		httpClient:   &http.Client{Timeout: cfg.RequestTimeout.Duration},
	}, nil
}

func (c *Client) Authenticate(ctx context.Context) error {
	switch c.auth.Method {
	case "token":
		token, err := config.ReadConfiguredSecret(c.auth.Token, c.auth.TokenFile, "vault token")
		if err != nil {
			c.setAuthErr(err)
			return err
		}
		c.setToken(token, false, 0)
		c.setAuthErr(nil)
		return nil
	case "approle":
		return c.loginAppRole(ctx)
	default:
		err := errors.New("unsupported vault auth method")
		c.setAuthErr(err)
		return err
	}
}

func (c *Client) StartRenewal(ctx context.Context, logger *slog.Logger) {
	if !c.tokenRenewal || c.auth.Method != "approle" {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	c.cancelRenew = cancel
	go c.renewLoop(ctx, logger)
}

func (c *Client) Close() {
	if c.cancelRenew != nil {
		c.cancelRenew()
	}
}

func (c *Client) Ready(ctx context.Context) error {
	if err := c.Health(ctx); err != nil {
		return err
	}
	if err := c.currentAuthErr(); err != nil {
		return fmt.Errorf("%w: auth unusable", ErrUnavailable)
	}
	if c.currentToken() == "" {
		if err := c.Authenticate(ctx); err != nil {
			return fmt.Errorf("%w: auth failed", ErrUnavailable)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL("auth/token/lookup-self"), nil)
	if err != nil {
		return err
	}
	c.addHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: token lookup failed", ErrUnavailable)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: token lookup failed", ErrUnavailable)
	}
	return nil
}

func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL("sys/health?standbyok=true&perfstandbyok=true"), nil)
	if err != nil {
		return err
	}
	c.addNamespace(req)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL(apiPath), nil)
	if err != nil {
		return nil, err
	}
	c.addHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: read failed", ErrUnavailable)
	}
	defer drainClose(resp.Body)
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && retryAuth && c.auth.Method == "approle" {
		if err := c.loginAppRole(ctx); err != nil {
			return nil, fmt.Errorf("%w: auth failed", ErrUnavailable)
		}
		return c.readKV(ctx, logicalPath, false)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%w: read failed", ErrUnavailable)
	}
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: invalid response", ErrUnavailable)
	}
	if out.Data.Data == nil {
		return nil, fmt.Errorf("%w: invalid kv v2 response", ErrUnavailable)
	}
	return out.Data.Data, nil
}

func (c *Client) loginAppRole(ctx context.Context) error {
	roleID, err := config.ReadConfiguredSecret(c.auth.RoleID, c.auth.RoleIDFile, "vault role_id")
	if err != nil {
		c.setAuthErr(err)
		return err
	}
	secretID, err := config.ReadConfiguredSecret(c.auth.SecretID, c.auth.SecretIDFile, "vault secret_id")
	if err != nil {
		c.setAuthErr(err)
		return err
	}
	body, err := json.Marshal(map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		c.setAuthErr(err)
		return err
	}
	authPath := path.Join("auth", strings.Trim(c.auth.MountPath, "/"), "login")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL(authPath), bytes.NewReader(body))
	if err != nil {
		c.setAuthErr(err)
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.addNamespace(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("%w: approle login failed", ErrUnavailable)
		c.setAuthErr(err)
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err = fmt.Errorf("%w: approle login failed", ErrUnavailable)
		c.setAuthErr(err)
		return err
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			Renewable     bool   `json:"renewable"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		err = fmt.Errorf("%w: invalid approle response", ErrUnavailable)
		c.setAuthErr(err)
		return err
	}
	if out.Auth.ClientToken == "" {
		err = fmt.Errorf("%w: approle response missing token", ErrUnavailable)
		c.setAuthErr(err)
		return err
	}
	c.setToken(out.Auth.ClientToken, out.Auth.Renewable, time.Duration(out.Auth.LeaseDuration)*time.Second)
	c.setAuthErr(nil)
	return nil
}

func (c *Client) renewLoop(ctx context.Context, logger *slog.Logger) {
	for {
		sleep := c.renewSleep()
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
		if !c.isRenewable() {
			if err := c.loginAppRole(ctx); err != nil && logger != nil {
				logger.Warn("vault relogin failed", "error_code", "vault_auth_failed")
			}
			continue
		}
		if err := c.renewSelf(ctx); err != nil {
			if logger != nil {
				logger.Warn("vault token renewal failed", "error_code", "vault_token_renewal_failed")
			}
			if err := c.loginAppRole(ctx); err != nil && logger != nil {
				logger.Warn("vault relogin failed", "error_code", "vault_auth_failed")
			}
		}
	}
}

func (c *Client) renewSelf(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL("auth/token/renew-self"), nil)
	if err != nil {
		c.setAuthErr(err)
		return err
	}
	c.addHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("%w: token renewal failed", ErrUnavailable)
		c.setAuthErr(err)
		return err
	}
	defer drainClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err = fmt.Errorf("%w: token renewal failed", ErrUnavailable)
		c.setAuthErr(err)
		return err
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			Renewable     bool   `json:"renewable"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&out); err != nil {
		err = fmt.Errorf("%w: invalid renewal response", ErrUnavailable)
		c.setAuthErr(err)
		return err
	}
	if out.Auth.ClientToken != "" {
		c.setToken(out.Auth.ClientToken, out.Auth.Renewable, time.Duration(out.Auth.LeaseDuration)*time.Second)
	}
	c.setAuthErr(nil)
	return nil
}

func KV2DataPath(mount, logicalPath string) (string, error) {
	if err := ValidateLogicalPath(logicalPath); err != nil {
		return "", err
	}
	mount = strings.Trim(mount, "/")
	if mount == "" {
		return "", errors.New("kv mount is empty")
	}
	return path.Join(mount, "data", logicalPath), nil
}

func ValidateLogicalPath(p string) error {
	if p == "" {
		return errors.New("vault path is empty")
	}
	if strings.HasPrefix(p, "/") {
		return errors.New("vault path must not start with slash")
	}
	if p == "." || p == ".." || strings.Contains(p, "../") || strings.Contains(p, "/..") {
		return errors.New("vault path must not contain parent traversal")
	}
	if strings.HasPrefix(p, "data/") || strings.Contains(p, "/data/") {
		return errors.New("vault path must not include KV v2 data/ prefix")
	}
	return nil
}

func (c *Client) apiURL(apiPath string) string {
	u, _ := url.JoinPath(c.address, "v1")
	if strings.Contains(apiPath, "?") {
		parts := strings.SplitN(apiPath, "?", 2)
		base, _ := url.JoinPath(u, parts[0])
		return base + "?" + parts[1]
	}
	out, _ := url.JoinPath(u, apiPath)
	return out
}

func (c *Client) addHeaders(req *http.Request) {
	c.addNamespace(req)
	if token := c.currentToken(); token != "" {
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

func (c *Client) currentAuthErr() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.authErr
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
	return time.Minute
}

func (c *Client) setToken(token string, renewable bool, leaseDuration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
	c.renewable = renewable
	c.leaseDuration = leaseDuration
}

func (c *Client) setAuthErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authErr = err
}

func drainClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}
