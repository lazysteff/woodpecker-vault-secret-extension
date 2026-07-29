package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maxResponseBytes int64 = 2 << 20

const maxLeaseSeconds = int64(1<<63-1) / int64(time.Second)

var errLimitedUseToken = errors.New("vault token must allow unlimited uses")

type authResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		Renewable     bool   `json:"renewable"`
		LeaseDuration int64  `json:"lease_duration"`
	} `json:"auth"`
}

type tokenState struct {
	token         string
	renewable     bool
	leaseDuration time.Duration
}

type tokenLookupResponse struct {
	Data struct {
		NumUses *int64 `json:"num_uses"`
	} `json:"data"`
}

func (r tokenLookupResponse) validateUnlimitedUses() error {
	if r.Data.NumUses == nil || *r.Data.NumUses < 0 {
		return errors.New("token lookup response contains an invalid use limit")
	}
	if *r.Data.NumUses != 0 {
		return errLimitedUseToken
	}
	return nil
}

func (r authResponse) tokenState() (tokenState, error) {
	if r.Auth.ClientToken == "" || r.Auth.ClientToken != strings.TrimSpace(r.Auth.ClientToken) {
		return tokenState{}, errors.New("auth response contains an invalid client token")
	}
	if r.Auth.LeaseDuration <= 0 || r.Auth.LeaseDuration > maxLeaseSeconds {
		return tokenState{}, errors.New("auth response contains an invalid lease duration")
	}
	return tokenState{
		token:         r.Auth.ClientToken,
		renewable:     r.Auth.Renewable,
		leaseDuration: time.Duration(r.Auth.LeaseDuration) * time.Second,
	}, nil
}

func decodeJSONResponse(body io.Reader, dst any) error {
	limited := &io.LimitedReader{R: body, N: maxResponseBytes + 1}
	payload, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(payload)) > maxResponseBytes {
		return errors.New("response exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("response contains multiple JSON values")
		}
		return fmt.Errorf("invalid trailing response data: %w", err)
	}
	return nil
}
