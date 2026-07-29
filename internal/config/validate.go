package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

func (c *Config) Validate() error {
	if c.Server.MaxBodyBytes <= 0 {
		return errors.New("server.max_body_bytes must be positive")
	}
	if c.Server.ReadTimeout.Duration <= 0 {
		return errors.New("server.read_timeout must be positive")
	}
	if c.Server.WriteTimeout.Duration <= 0 {
		return errors.New("server.write_timeout must be positive")
	}
	if c.Server.IdleTimeout.Duration <= 0 {
		return errors.New("server.idle_timeout must be positive")
	}
	if c.Logging.Format != "json" && c.Logging.Format != "text" {
		return errors.New("logging.format must be json or text")
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("logging.level must be debug, info, warn, or error")
	}
	if err := c.Woodpecker.Validate(); err != nil {
		return err
	}
	if err := c.Vault.Validate(); err != nil {
		return err
	}
	for i := range c.Rules {
		if err := c.Rules[i].Validate(i); err != nil {
			return err
		}
	}
	return nil
}

func (w WoodpeckerConfig) Validate() error {
	hasInline := strings.TrimSpace(w.PublicKey) != ""
	hasFile := strings.TrimSpace(w.PublicKeyFile) != ""
	if hasInline == hasFile {
		return errors.New("exactly one of woodpecker.public_key or woodpecker.public_key_file must be configured")
	}
	if w.Netrc.Enabled {
		return errors.New("woodpecker.netrc.enabled is not supported in v1")
	}
	return nil
}

func (v VaultConfig) Validate() error {
	address := strings.TrimSpace(v.Address)
	if address == "" {
		return errors.New("vault.address is required")
	}
	if address != v.Address {
		return errors.New("vault.address must not contain surrounding whitespace")
	}
	if strings.HasSuffix(address, "/") {
		return errors.New("vault.address must not end with slash")
	}
	parsedAddress, err := url.Parse(address)
	if err != nil || (parsedAddress.Scheme != "http" && parsedAddress.Scheme != "https") || parsedAddress.Host == "" || parsedAddress.User != nil || parsedAddress.RawQuery != "" || parsedAddress.Fragment != "" {
		return errors.New("vault.address must be an http or https URL without user info, query, or fragment")
	}
	if v.KV.Version != 2 {
		return errors.New("only vault.kv.version 2 is supported")
	}
	if v.RequestTimeout.Duration <= 0 {
		return errors.New("vault.request_timeout must be positive")
	}
	if !validMountPath(v.KV.Mount) {
		return errors.New("vault.kv.mount must be a logical mount name")
	}
	switch v.Auth.Method {
	case "token":
		if err := validateInlineSecret(v.Auth.Token, "vault token"); err != nil {
			return err
		}
		if exactlyOne(v.Auth.Token, v.Auth.TokenFile) != nil {
			return errors.New("vault.auth token method requires exactly one of token or token_file")
		}
		if v.TokenRenewal {
			return errors.New("vault.token_renewal is supported only with approle authentication")
		}
	case "approle":
		if !validMountPath(v.Auth.MountPath) {
			return errors.New("vault.auth.mount_path must be a logical mount name")
		}
		if err := validateInlineSecret(v.Auth.RoleID, "vault role_id"); err != nil {
			return err
		}
		if err := validateInlineSecret(v.Auth.SecretID, "vault secret_id"); err != nil {
			return err
		}
		if exactlyOne(v.Auth.RoleID, v.Auth.RoleIDFile) != nil {
			return errors.New("vault.auth approle method requires exactly one of role_id or role_id_file")
		}
		if exactlyOne(v.Auth.SecretID, v.Auth.SecretIDFile) != nil {
			return errors.New("vault.auth approle method requires exactly one of secret_id or secret_id_file")
		}
	default:
		return errors.New("vault.auth.method must be token or approle")
	}
	return nil
}

func validMountPath(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func exactlyOne(a, b string) error {
	hasA := strings.TrimSpace(a) != ""
	hasB := strings.TrimSpace(b) != ""
	if hasA == hasB {
		return errors.New("expected exactly one value")
	}
	return nil
}

func (r RuleConfig) Validate(index int) error {
	prefix := fmt.Sprintf("rules[%d]", index)
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("%s.id is required", prefix)
	}
	if strings.TrimSpace(r.Repo) == "" {
		return fmt.Errorf("%s.repo is required", prefix)
	}
	for i, event := range r.Events {
		if event == "" || event != strings.TrimSpace(event) {
			return fmt.Errorf("%s.events[%d] must be a non-empty event without surrounding whitespace", prefix, i)
		}
	}
	for _, selectors := range []struct {
		name   string
		values []string
	}{
		{name: "refs", values: r.Refs},
		{name: "tags", values: r.Tags},
	} {
		for i, value := range selectors.values {
			if value == "" || value != strings.TrimSpace(value) {
				return fmt.Errorf("%s.%s[%d] must be a non-empty pattern without surrounding whitespace", prefix, selectors.name, i)
			}
		}
	}
	if r.Partial {
		return fmt.Errorf("%s.partial=true is not supported in v1", prefix)
	}
	if len(r.Secrets) == 0 {
		return fmt.Errorf("%s.secrets must not be empty", prefix)
	}
	secretNames := make(map[string]struct{}, len(r.Secrets))
	for i, s := range r.Secrets {
		sp := fmt.Sprintf("%s.secrets[%d]", prefix, i)
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("%s.name is required", sp)
		}
		if _, exists := secretNames[s.Name]; exists {
			return fmt.Errorf("%s.name duplicates another secret in the same rule", sp)
		}
		secretNames[s.Name] = struct{}{}
		if strings.TrimSpace(s.Field) == "" {
			return fmt.Errorf("%s.field is required", sp)
		}
		if err := ValidateLogicalPath(s.Path); err != nil {
			return fmt.Errorf("%s.path: %w", sp, err)
		}
	}
	return nil
}

func ValidateLogicalPath(path string) error {
	if path == "" {
		return errors.New("must not be empty")
	}
	if strings.HasPrefix(path, "/") {
		return errors.New("must not start with slash")
	}
	for _, segment := range strings.Split(path, "/") {
		switch segment {
		case "":
			return errors.New("must not contain empty path segments")
		case ".", "..":
			return errors.New("must not contain dot path segments")
		}
	}
	if strings.HasPrefix(path, "data/") {
		return errors.New("must not include KV v2 data/ prefix")
	}
	return nil
}
