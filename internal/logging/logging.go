package logging

import (
	"io"
	"log/slog"
	"os"

	"github.com/stephan/woodpecker-vault-secret-extension/internal/config"
)

func New(cfg config.LoggingConfig) *slog.Logger {
	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	return NewWithWriter(cfg, os.Stdout, level)
}

func NewWithWriter(cfg config.LoggingConfig, w io.Writer, level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
