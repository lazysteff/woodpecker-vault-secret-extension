package signature

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/yaronf/httpsign"
)

const SignatureName = "woodpecker-ci-extensions"

type Verifier struct {
	inner        *httpsign.Verifier
	maxBodyBytes int64
}

func ParsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, errors.New("public key is empty")
	}
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("public key is not Ed25519")
		}
		return pub, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, errors.New("invalid Ed25519 public key format")
}

func NewVerifier(pub ed25519.PublicKey, maxBodyBytes int64) (*Verifier, error) {
	cfg := httpsign.NewVerifyConfig().
		SetAllowedAlgs([]string{"ed25519"}).
		SetMaxBodySize(maxBodyBytes)
	inner, err := httpsign.NewEd25519Verifier(pub, cfg, httpsign.Headers("@request-target", "content-digest"))
	if err != nil {
		return nil, err
	}
	return &Verifier{inner: inner, maxBodyBytes: maxBodyBytes}, nil
}

func (v *Verifier) Verify(r *http.Request) error {
	if v == nil || v.inner == nil {
		return errors.New("signature verifier is not initialized")
	}
	if err := httpsign.ValidateContentDigestHeader(
		r.Header.Values("Content-Digest"),
		&r.Body,
		[]string{httpsign.DigestSha256},
		httpsign.NewDigestOptions().SetMaxBodySize(v.maxBodyBytes),
	); err != nil {
		return err
	}
	return httpsign.VerifyRequest(SignatureName, *v.inner, r)
}
