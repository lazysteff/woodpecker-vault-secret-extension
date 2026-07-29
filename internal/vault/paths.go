package vault

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
)

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
	return config.ValidateLogicalPath(p)
}

func (c *Client) apiURL(apiPath string) (string, error) {
	segments := strings.Split(apiPath, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	endpoint, err := url.JoinPath(c.address, "v1", strings.Join(segments, "/"))
	if err != nil {
		return "", fmt.Errorf("invalid vault API path: %w", err)
	}
	return endpoint, nil
}

func (c *Client) apiURLWithQuery(apiPath string, query url.Values) (string, error) {
	endpoint, err := c.apiURL(apiPath)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid vault API URL: %w", err)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}
