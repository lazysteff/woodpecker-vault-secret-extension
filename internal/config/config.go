package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	if value.Value == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Logging    LoggingConfig    `yaml:"logging"`
	Woodpecker WoodpeckerConfig `yaml:"woodpecker"`
	Vault      VaultConfig      `yaml:"vault"`
	Rules      []RuleConfig     `yaml:"rules"`
}

type ServerConfig struct {
	ListenAddr   string   `yaml:"listen_addr"`
	ReadTimeout  Duration `yaml:"read_timeout"`
	WriteTimeout Duration `yaml:"write_timeout"`
	IdleTimeout  Duration `yaml:"idle_timeout"`
	MaxBodyBytes int64    `yaml:"max_body_bytes"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type WoodpeckerConfig struct {
	PublicKey     string      `yaml:"public_key"`
	PublicKeyFile string      `yaml:"public_key_file"`
	Netrc         NetrcConfig `yaml:"netrc"`
}

type NetrcConfig struct {
	Enabled bool `yaml:"enabled"`
}

type VaultConfig struct {
	Address        string          `yaml:"address"`
	Namespace      string          `yaml:"namespace"`
	Auth           VaultAuthConfig `yaml:"auth"`
	KV             VaultKVConfig   `yaml:"kv"`
	RequestTimeout Duration        `yaml:"request_timeout"`
	TokenRenewal   bool            `yaml:"token_renewal"`
}

type VaultAuthConfig struct {
	Method       string `yaml:"method"`
	MountPath    string `yaml:"mount_path"`
	Token        string `yaml:"token"`
	TokenFile    string `yaml:"token_file"`
	RoleID       string `yaml:"role_id"`
	RoleIDFile   string `yaml:"role_id_file"`
	SecretID     string `yaml:"secret_id"`
	SecretIDFile string `yaml:"secret_id_file"`
}

type VaultKVConfig struct {
	Version int    `yaml:"version"`
	Mount   string `yaml:"mount"`
}

type RuleConfig struct {
	ID                string         `yaml:"id"`
	Repo              string         `yaml:"repo"`
	Events            []string       `yaml:"events"`
	Branches          []string       `yaml:"branches"`
	Refs              []string       `yaml:"refs"`
	Tags              []string       `yaml:"tags"`
	AllowPullRequests bool           `yaml:"allow_pull_requests"`
	AllowForks        bool           `yaml:"allow_forks"`
	AllowOverride     bool           `yaml:"allow_override"`
	Partial           bool           `yaml:"partial"`
	Secrets           []SecretConfig `yaml:"secrets"`
}

type SecretConfig struct {
	Name   string   `yaml:"name"`
	Path   string   `yaml:"path"`
	Field  string   `yaml:"field"`
	Events []string `yaml:"events"`
	Images []string `yaml:"images"`
}

var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func LoadFile(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadBytes(b)
}

func LoadBytes(b []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := expandConfigEnv(&cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func expandConfigEnv(cfg *Config) error {
	missing := map[string]struct{}{}
	expandValue(reflect.ValueOf(cfg).Elem(), missing)
	if len(missing) > 0 {
		names := make([]string, 0, len(missing))
		for name := range missing {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("missing environment variables: %s", strings.Join(names, ", "))
	}
	return nil
}

func expandValue(v reflect.Value, missing map[string]struct{}) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			v.SetString(expandString(v.String(), missing))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			expandValue(v.Field(i), missing)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			expandValue(v.Index(i), missing)
		}
	case reflect.Pointer:
		if !v.IsNil() {
			expandValue(v.Elem(), missing)
		}
	}
}

func expandString(s string, missing map[string]struct{}) string {
	return envPattern.ReplaceAllStringFunc(s, func(match string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(match, "${"), "}")
		value, ok := os.LookupEnv(name)
		if !ok {
			missing[name] = struct{}{}
			return ""
		}
		return value
	})
}

func (c *Config) applyDefaults() {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = ":8080"
	}
	if c.Server.ReadTimeout.Duration == 0 {
		c.Server.ReadTimeout.Duration = 5 * time.Second
	}
	if c.Server.WriteTimeout.Duration == 0 {
		c.Server.WriteTimeout.Duration = 10 * time.Second
	}
	if c.Server.IdleTimeout.Duration == 0 {
		c.Server.IdleTimeout.Duration = 60 * time.Second
	}
	if c.Server.MaxBodyBytes == 0 {
		c.Server.MaxBodyBytes = 1 << 20
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Vault.Auth.MountPath == "" {
		c.Vault.Auth.MountPath = "approle"
	}
	if c.Vault.KV.Version == 0 {
		c.Vault.KV.Version = 2
	}
	if c.Vault.KV.Mount == "" {
		c.Vault.KV.Mount = "kv"
	}
	if c.Vault.RequestTimeout.Duration == 0 {
		c.Vault.RequestTimeout.Duration = 5 * time.Second
	}
}

func (c *Config) Validate() error {
	if c.Server.MaxBodyBytes <= 0 {
		return errors.New("server.max_body_bytes must be positive")
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

func (w WoodpeckerConfig) PublicKeyMaterial() ([]byte, error) {
	if strings.TrimSpace(w.PublicKey) != "" {
		return []byte(w.PublicKey), nil
	}
	b, err := os.ReadFile(w.PublicKeyFile)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, errors.New("woodpecker public key file is empty")
	}
	return b, nil
}

func (v VaultConfig) Validate() error {
	if strings.TrimSpace(v.Address) == "" {
		return errors.New("vault.address is required")
	}
	if strings.HasSuffix(strings.TrimSpace(v.Address), "/") {
		return errors.New("vault.address must not end with slash")
	}
	if v.KV.Version != 2 {
		return errors.New("only vault.kv.version 2 is supported")
	}
	if strings.TrimSpace(v.KV.Mount) == "" {
		return errors.New("vault.kv.mount is required")
	}
	if strings.HasPrefix(v.KV.Mount, "/") || strings.Contains(v.KV.Mount, "../") {
		return errors.New("vault.kv.mount must be a logical mount name")
	}
	switch v.Auth.Method {
	case "token":
		if exactlyOne(v.Auth.Token, v.Auth.TokenFile) != nil {
			return errors.New("vault.auth token method requires exactly one of token or token_file")
		}
	case "approle":
		if strings.TrimSpace(v.Auth.MountPath) == "" {
			return errors.New("vault.auth.mount_path is required for approle")
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
	if r.Partial {
		return fmt.Errorf("%s.partial=true is not supported in v1", prefix)
	}
	if len(r.Secrets) == 0 {
		return fmt.Errorf("%s.secrets must not be empty", prefix)
	}
	for i, s := range r.Secrets {
		sp := fmt.Sprintf("%s.secrets[%d]", prefix, i)
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("%s.name is required", sp)
		}
		if strings.TrimSpace(s.Field) == "" {
			return fmt.Errorf("%s.field is required", sp)
		}
		if err := validateLogicalPath(s.Path); err != nil {
			return fmt.Errorf("%s.path: %w", sp, err)
		}
	}
	return nil
}

func validateLogicalPath(path string) error {
	if path == "" {
		return errors.New("must not be empty")
	}
	if strings.HasPrefix(path, "/") {
		return errors.New("must not start with slash")
	}
	if path == "." || path == ".." || strings.Contains(path, "../") || strings.Contains(path, "/..") {
		return errors.New("must not contain parent traversal")
	}
	if strings.Contains(path, "/data/") || strings.HasPrefix(path, "data/") {
		return errors.New("must not include KV v2 data/ prefix")
	}
	return nil
}

func ReadConfiguredSecret(value, filePath, name string) (string, error) {
	if strings.TrimSpace(value) != "" {
		return value, nil
	}
	b, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("read %s file: %w", name, err)
	}
	out := strings.TrimSpace(string(b))
	if out == "" {
		return "", fmt.Errorf("%s file is empty", name)
	}
	return out, nil
}
