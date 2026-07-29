package main

import (
	"context"
	"log"
	"net"
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
	os.Exit(run())
}

func run() int {
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = "config.yml"
	}
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		log.Printf("load config: %v", err)
		return 1
	}
	logger := logging.New(cfg.Logging)

	pubMaterial, err := cfg.Woodpecker.PublicKeyMaterial()
	if err != nil {
		logger.Error("load woodpecker public key failed", "error_code", "woodpecker_public_key_failed")
		return 1
	}
	pubKey, err := signature.ParsePublicKey(pubMaterial)
	if err != nil {
		logger.Error("parse woodpecker public key failed", "error_code", "woodpecker_public_key_failed")
		return 1
	}
	verifier, err := signature.NewVerifier(pubKey, cfg.Server.MaxBodyBytes)
	if err != nil {
		logger.Error("initialize signature verifier failed", "error_code", "signature_verifier_failed")
		return 1
	}

	vaultClient, err := vault.New(cfg.Vault)
	if err != nil {
		logger.Error("initialize vault client failed", "error_code", "vault_client_failed")
		return 1
	}
	app := httpserver.New(cfg.Server, cfg.Rules, verifier, vaultClient, logger)
	server := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      app.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout.Duration,
		WriteTimeout: cfg.Server.WriteTimeout.Duration,
		IdleTimeout:  cfg.Server.IdleTimeout.Duration,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.Error("server failed", "error_code", "server_failed")
		return 1
	}
	// Serve closes the listener after startup succeeds; this also closes it on
	// every authentication or initialization failure before Serve takes over.
	defer listener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	authCtx, cancel := context.WithTimeout(ctx, cfg.Vault.RequestTimeout.Duration)
	if err := vaultClient.Authenticate(authCtx); err != nil {
		cancel()
		logger.Error("vault authentication failed", "error_code", "vault_auth_failed")
		return 1
	}
	cancel()
	// Renewal belongs to the server lifecycle, not the signal lifecycle: active
	// requests may still need the current token while graceful shutdown drains.
	vaultClient.StartRenewal(context.Background(), logger)
	defer vaultClient.Close()

	logger.Info("starting server", "listen_addr", cfg.Server.ListenAddr)
	if err := serveHTTP(ctx, server, listener, 10*time.Second); err != nil {
		logger.Error("server failed", "error_code", "server_failed")
		return 1
	}
	return 0
}
