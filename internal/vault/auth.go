package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
)

func (c *Client) Authenticate(ctx context.Context) error {
	switch c.auth.Method {
	case "token":
		token, err := config.ReadConfiguredSecret(c.auth.Token, c.auth.TokenFile, "vault token")
		if err != nil {
			return err
		}
		valid, err := c.newTokenUsable(ctx, token)
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("%w: token lookup failed", ErrUnavailable)
		}
		c.setToken(token, false, 0)
		return nil
	case "approle":
		return c.loginAppRole(ctx)
	default:
		return errors.New("unsupported vault auth method")
	}
}

func (c *Client) StartRenewal(ctx context.Context, logger *slog.Logger) {
	if !c.tokenRenewal || c.auth.Method != "approle" {
		return
	}
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	if c.cancelRenew != nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	c.cancelRenew = cancel
	c.renewDone = done
	go func() {
		defer close(done)
		c.renewLoop(ctx, logger)
	}()
}

func (c *Client) Close() {
	c.renewMu.Lock()
	cancel := c.cancelRenew
	done := c.renewDone
	c.renewMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
	c.renewMu.Lock()
	if c.renewDone == done {
		c.cancelRenew = nil
		c.renewDone = nil
	}
	c.renewMu.Unlock()
}

func (c *Client) loginAppRole(ctx context.Context) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	return c.loginAppRoleLocked(ctx)
}

func (c *Client) reauthenticateAppRole(ctx context.Context, rejectedToken string) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if token := c.currentToken(); token != "" && token != rejectedToken {
		return nil
	}
	return c.loginAppRoleLocked(ctx)
}

func (c *Client) lookupSelf(ctx context.Context, retryAuth bool) error {
	usedToken := c.currentToken()
	valid, err := c.tokenValid(ctx, usedToken)
	if err != nil {
		return err
	}
	if valid {
		return nil
	}
	if retryAuth && c.auth.Method == "approle" {
		if err := c.reauthenticateAppRole(ctx, usedToken); err != nil {
			return fmt.Errorf("auth failed: %w", err)
		}
		return c.lookupSelf(ctx, false)
	}
	return fmt.Errorf("%w: token lookup failed", ErrUnavailable)
}

func (c *Client) tokenValid(ctx context.Context, token string) (bool, error) {
	endpoint, err := c.apiURL("auth/token/lookup-self")
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	c.addHeadersWithToken(req, token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("%w: token lookup failed", ErrUnavailable)
	}
	defer drainClose(resp.Body)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		var out tokenLookupResponse
		if err := decodeJSONResponse(resp.Body, &out); err != nil {
			return false, fmt.Errorf("%w: invalid token lookup response", ErrUnavailable)
		}
		if err := out.validateUnlimitedUses(); err != nil {
			return false, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return true, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("%w: token lookup failed", ErrUnavailable)
	}
}

// newTokenUsable verifies both that Vault identifies the token as unlimited-use
// and that the lookup itself did not exhaust a finite-use token whose remaining
// use count was reported as zero. Only new tokens need the second probe; tokens
// already installed in the client have passed this admission check.
func (c *Client) newTokenUsable(ctx context.Context, token string) (bool, error) {
	for range 2 {
		valid, err := c.tokenValid(ctx, token)
		if err != nil || !valid {
			return valid, err
		}
	}

	return true, nil
}

func (c *Client) loginAppRoleLocked(ctx context.Context) error {
	if c.isAppRoleLoginBlocked() {
		return fmt.Errorf("%w: %w", ErrUnavailable, errAppRoleLoginBlocked)
	}
	roleID, err := config.ReadConfiguredSecret(c.auth.RoleID, c.auth.RoleIDFile, "vault role_id")
	if err != nil {
		return err
	}
	secretID, err := config.ReadConfiguredSecret(c.auth.SecretID, c.auth.SecretIDFile, "vault secret_id")
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return err
	}
	authPath := path.Join("auth", strings.Trim(c.auth.MountPath, "/"), "login")
	endpoint, err := c.apiURL(authPath)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c.addNamespace(req)
	var requestWritten atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				requestWritten.Store(true)
			}
		},
	}))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Once the complete login request has reached the transport, a missing
		// response is indeterminate: Vault may have consumed the Secret ID and
		// issued a token. Do not risk consuming another credential use.
		if requestWritten.Load() {
			c.blockAppRoleLogin()
		}
		return fmt.Errorf("%w: approle login failed", ErrUnavailable)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: approle login failed", ErrUnavailable)
	}
	var out authResponse
	if err := decodeJSONResponse(resp.Body, &out); err != nil {
		// Vault accepted the login request, so retrying with the same AppRole
		// credentials could consume another Secret ID use without recovering
		// the token that may already have been issued.
		c.blockAppRoleLogin()
		return fmt.Errorf("%w: invalid approle response", ErrUnavailable)
	}
	state, err := out.tokenState()
	if err != nil {
		c.blockAppRoleLogin()
		return fmt.Errorf("%w: invalid approle response", ErrUnavailable)
	}
	return c.installAppRoleToken(ctx, state)
}

func (c *Client) installAppRoleToken(ctx context.Context, state tokenState) error {
	valid, err := c.newTokenUsable(ctx, state.token)
	if err != nil {
		// Once Vault has issued a candidate, never discard it and immediately
		// consume another AppRole login. Any admission failure requires an
		// operator-visible restart after the upstream condition is corrected.
		c.blockAppRoleLogin()
		return fmt.Errorf("%w: new approle token self-lookup failed", ErrUnavailable)
	}
	if !valid {
		c.blockAppRoleLogin()
		return fmt.Errorf("%w: new approle token cannot perform self-lookup", ErrUnavailable)
	}
	c.setToken(state.token, state.renewable, state.leaseDuration)
	return nil
}

func (c *Client) renewLoop(ctx context.Context, logger *slog.Logger) {
	timer := time.NewTimer(c.renewSleep())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.tokenChanged:
			resetTimer(timer, c.renewSleep())
			continue
		case <-timer.C:
		}
		renewErr, loginErr := c.maintainAppRoleToken(ctx)
		if ctx.Err() != nil {
			return
		}
		if renewErr != nil {
			if logger != nil {
				logger.Warn("vault token renewal failed", "error_code", "vault_token_renewal_failed")
			}
		}
		if loginErr != nil {
			logAppRoleLoginFailure(logger, loginErr)
		}
		next := c.renewSleep()
		if loginErr != nil {
			next = c.renewRetrySleep()
		}
		resetTimer(timer, next)
	}
}

func logAppRoleLoginFailure(logger *slog.Logger, err error) {
	if logger == nil {
		return
	}
	if errors.Is(err, errAppRoleLoginBlocked) {
		logger.Warn("vault AppRole login blocked; restart required", "error_code", "vault_auth_blocked")
		return
	}
	logger.Warn("vault relogin failed", "error_code", "vault_auth_failed")
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

// maintainAppRoleToken serializes the renewal decision, renewal request, and
// fallback login so a fallback can never overwrite a token installed by a
// concurrent request reauthentication.
func (c *Client) maintainAppRoleToken(ctx context.Context) (renewErr, loginErr error) {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if !c.isRenewable() {
		return nil, c.loginAppRoleLocked(ctx)
	}
	if err := c.renewSelfLocked(ctx); err != nil {
		return err, c.loginAppRoleLocked(ctx)
	}
	return nil, nil
}

func (c *Client) renewSelf(ctx context.Context) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	return c.renewSelfLocked(ctx)
}

func (c *Client) renewSelfLocked(ctx context.Context) error {
	endpoint, err := c.apiURL("auth/token/renew-self")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	c.addHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: token renewal failed", ErrUnavailable)
	}
	defer drainClose(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: token renewal failed", ErrUnavailable)
	}
	var out authResponse
	if err := decodeJSONResponse(resp.Body, &out); err != nil {
		return fmt.Errorf("%w: invalid renewal response", ErrUnavailable)
	}
	state, err := out.tokenState()
	if err != nil {
		return fmt.Errorf("%w: invalid renewal response", ErrUnavailable)
	}
	return c.installAppRoleToken(ctx, state)
}
