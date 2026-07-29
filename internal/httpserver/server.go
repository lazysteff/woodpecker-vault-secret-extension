package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/rules"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/signature"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/vault"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/woodpecker"
)

type SecretStore interface {
	Ready(context.Context) error
	ReadKV(context.Context, string) (map[string]any, error)
}

type Server struct {
	cfg      config.ServerConfig
	rules    rules.Engine
	verifier *signature.Verifier
	store    SecretStore
	logger   *slog.Logger
}

func New(cfg config.ServerConfig, ruleCfg []config.RuleConfig, verifier *signature.Verifier, store SecretStore, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		rules:    rules.NewEngine(ruleCfg),
		verifier: verifier,
		store:    store,
		logger:   logger,
	}
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serveHTTP)
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	case "/readyz":
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ReadTimeout.Duration)
		defer cancel()
		if err := s.store.Ready(ctx); err != nil {
			writeError(w, http.StatusServiceUnavailable, "not ready")
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	case "/secrets":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		s.handleSecrets(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := requestID(r)
	body, err := readLimited(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		s.log(requestID, http.StatusBadRequest, "", "", "", "", "", 0, "bad_request", start)
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := s.verifier.Verify(r); err != nil {
		s.log(requestID, http.StatusUnauthorized, "", "", "", "", "", 0, "unauthorized", start)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	req, err := woodpecker.Decode(body)
	if err != nil {
		s.log(requestID, http.StatusBadRequest, "", "", "", "", "", 0, "bad_request", start)
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	matches := s.rules.Match(*req)
	if len(matches) == 0 {
		s.log(requestID, http.StatusNoContent, req.RepoForLog(), req.Pipeline.Event, req.Pipeline.Branch, req.Pipeline.Ref, "none", 0, "", start)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	refs, err := rules.CollectSecretRefs(matches)
	if err != nil {
		s.log(requestID, http.StatusInternalServerError, req.RepoForLog(), req.Pipeline.Event, req.Pipeline.Branch, req.Pipeline.Ref, "matched", 0, "duplicate_secret_name", start)
		writeError(w, http.StatusInternalServerError, "configuration error")
		return
	}
	resolveCtx, cancel := s.resolutionContext(r.Context(), start)
	defer cancel()
	response, readCount, err := s.resolveSecrets(resolveCtx, refs)
	if err != nil {
		status, code, msg := classifyResolveError(err)
		s.log(requestID, status, req.RepoForLog(), req.Pipeline.Event, req.Pipeline.Branch, req.Pipeline.Ref, "matched", readCount, code, start)
		writeError(w, status, msg)
		return
	}
	payload, err := json.Marshal(woodpecker.Response{Secrets: response})
	if err != nil {
		s.log(requestID, http.StatusInternalServerError, req.RepoForLog(), req.Pipeline.Event, req.Pipeline.Branch, req.Pipeline.Ref, "matched", readCount, "response_encode_failed", start)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	payload = append(payload, '\n')
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if n, err := w.Write(payload); err != nil || n != len(payload) {
		s.log(requestID, http.StatusOK, req.RepoForLog(), req.Pipeline.Event, req.Pipeline.Branch, req.Pipeline.Ref, "matched", readCount, "response_write_failed", start)
		return
	}
	s.log(requestID, http.StatusOK, req.RepoForLog(), req.Pipeline.Event, req.Pipeline.Branch, req.Pipeline.Ref, "matched", readCount, "", start)
}

func (s *Server) resolutionContext(parent context.Context, requestStart time.Time) (context.Context, context.CancelFunc) {
	timeout := s.cfg.WriteTimeout.Duration
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	// Reserve part of the server's write budget for encoding and delivering the response.
	budget := timeout - timeout/10
	if budget <= 0 {
		budget = timeout
	}
	return context.WithDeadline(parent, requestStart.Add(budget))
}

func (s *Server) resolveSecrets(ctx context.Context, refs []rules.SecretRef) ([]woodpecker.Secret, int, error) {
	cache := map[string]map[string]any{}
	out := make([]woodpecker.Secret, 0, len(refs))
	readCount := 0
	for _, ref := range refs {
		data, ok := cache[ref.Path]
		if !ok {
			var err error
			data, err = s.store.ReadKV(ctx, ref.Path)
			if err != nil {
				return nil, readCount, err
			}
			cache[ref.Path] = data
			readCount++
		}
		raw, ok := data[ref.Field]
		if !ok {
			return nil, readCount, errMissingField
		}
		value, ok := raw.(string)
		if !ok {
			return nil, readCount, errNonStringField
		}
		out = append(out, woodpecker.Secret{
			Name:   ref.Name,
			Value:  value,
			Events: ref.Events,
			Images: ref.Images,
		})
	}
	return out, readCount, nil
}

var (
	errMissingField   = errors.New("missing vault field")
	errNonStringField = errors.New("non-string vault field")
)

func classifyResolveError(err error) (int, string, string) {
	if errors.Is(err, vault.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return http.StatusServiceUnavailable, "vault_read_failed", "vault read failed"
	}
	if errors.Is(err, errMissingField) {
		return http.StatusInternalServerError, "missing_vault_field", "secret resolution failed"
	}
	if errors.Is(err, errNonStringField) {
		return http.StatusInternalServerError, "non_string_vault_field", "secret resolution failed"
	}
	return http.StatusInternalServerError, "internal_error", "internal error"
}

func readLimited(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func requestID(r *http.Request) string {
	for _, header := range []string{"X-Request-ID", "Request-ID"} {
		if v := r.Header.Get(header); validRequestID(v) {
			return v
		}
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

func validRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i := range len(value) {
		if value[i] < '!' || value[i] > '~' {
			return false
		}
	}
	return true
}

func (s *Server) log(requestID string, status int, repo, event, branch, ref, matchResult string, vaultReadCount int, errorCode string, start time.Time) {
	fields := []any{
		"request_id", requestID,
		"status_code", status,
		"duration_ms", time.Since(start).Milliseconds(),
	}
	if repo != "" {
		fields = append(fields, "repo", repo)
	}
	if event != "" {
		fields = append(fields, "event", event)
	}
	if branch != "" {
		fields = append(fields, "branch", branch)
	}
	if ref != "" {
		fields = append(fields, "ref", ref)
	}
	if matchResult != "" {
		fields = append(fields, "match_result", matchResult)
	}
	if vaultReadCount > 0 {
		fields = append(fields, "vault_read_count", vaultReadCount)
	}
	if errorCode != "" {
		fields = append(fields, "error_code", errorCode)
	}
	if errorCode == "response_write_failed" {
		fields = append(fields, "delivery_result", "failed")
	}
	s.logger.Info("request completed", fields...)
}
