package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("multiple YAML documents are not supported")
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
