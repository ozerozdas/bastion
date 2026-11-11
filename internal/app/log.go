package app

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// LogFormat values accepted by --log-format.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// LogConfig configures bastion's own logger. Empty fields mean the defaults
// (text format, info level).
type LogConfig struct {
	Format string
	Level  string
}

// NewLogger builds bastion's slog logger. It does not install it as the
// process default; use SetupLogging for that.
func NewLogger(w io.Writer, cfg LogConfig) (*slog.Logger, error) {
	var level slog.Level
	if cfg.Level != "" {
		if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
			return nil, fmt.Errorf("invalid log level %q (want debug, info, warn or error): %w", cfg.Level, err)
		}
	}

	opts := &slog.HandlerOptions{Level: level}
	switch cfg.Format {
	case "", LogFormatText:
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case LogFormatJSON:
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q (want %q or %q)", cfg.Format, LogFormatText, LogFormatJSON)
	}
}

// SetupLogging builds bastion's logger and installs it as slog.Default.
//
// Trivy's pkg/log runs an init() that replaces slog.Default() with a buffering
// handler which silently drops records until Trivy initialises its own logger
// (ADR-001). Because all init()s run before main(), every bastion entrypoint
// must call SetupLogging after flag parsing and before doing work. The pointer
// check below turns a handler that did not take effect into a hard error
// instead of a silently lost log line.
func SetupLogging(w io.Writer, cfg LogConfig) (*slog.Logger, error) {
	logger, err := NewLogger(w, cfg)
	if err != nil {
		return nil, err
	}
	slog.SetDefault(logger)
	if slog.Default() != logger {
		return nil, errors.New("app: slog.Default() did not keep bastion's handler")
	}
	logger.Debug("logging configured", "format", cfg.Format, "log_level", cfg.Level)
	return logger, nil
}
