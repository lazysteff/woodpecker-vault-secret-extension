package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

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

func ReadConfiguredSecret(value, filePath, name string) (string, error) {
	if err := validateInlineSecret(value, name); err != nil {
		return "", err
	}
	if value != "" {
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

func validateInlineSecret(value, name string) error {
	if value != strings.TrimSpace(value) {
		return fmt.Errorf("%s must not contain surrounding whitespace", name)
	}
	return nil
}
