package config

import (
	"fmt"
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
