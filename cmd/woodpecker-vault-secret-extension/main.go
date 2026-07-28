package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/httpserver"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/logging"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/signature"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/vault"
)

func main() {
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = "config.yml"
	}
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	logger := logging.New(cfg.Logging)

	pubMaterial, err := cfg.Woodpecker.PublicKeyMaterial()
	if err != nil {
		logger.Error("load woodpecker public key failed", "error_code", "woodpecker_public_key_failed")
		os.Exit(1)
	}
	pubKey, err := signature.ParsePublicKey(pubMaterial)
	if err != nil {
		logger.Error("parse woodpecker public key failed", "error_code", "woodpecker_public_key_failed")
		os.Exit(1)
	}
	verifier, err := signature.NewVerifier(pubKey, cfg.Server.MaxBodyBytes)
	if err != nil {
		logger.Error("initialize signature verifier failed", "error_code", "signature_verifier_failed")
		os.Exit(1)
	}

	vaultClient, err := vault.New(cfg.Vault)
	if err != nil {
		logger.Error("initialize vault client failed", "error_code", "vault_client_failed")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	authCtx, cancel := context.WithTimeout(ctx, cfg.Vault.RequestTimeout.Duration)
	if err := vaultClient.Authenticate(authCtx); err != nil {
		cancel()
		logger.Error("vault authentication failed", "error_code", "vault_auth_failed")
		os.Exit(1)
	}
	cancel()
	vaultClient.StartRenewal(ctx, logger)
	defer vaultClient.Close()

	app := httpserver.New(cfg.Server, cfg.Rules, verifier, vaultClient, logger)
	server := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      app.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout.Duration,
		WriteTimeout: cfg.Server.WriteTimeout.Duration,
		IdleTimeout:  cfg.Server.IdleTimeout.Duration,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Info("starting server", "listen_addr", cfg.Server.ListenAddr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error_code", "server_failed")
		os.Exit(1)
	}
}
