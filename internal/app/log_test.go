package app

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerFormats(t *testing.T) {
	tests := []struct {
		name   string
		cfg    LogConfig
		log    func(*slog.Logger)
		assert func(t *testing.T, line string)
	}{
		{
			name: "text default",
			cfg:  LogConfig{},
			log:  func(l *slog.Logger) { l.Info("hello") },
			assert: func(t *testing.T, line string) {
				t.Helper()
				if !strings.Contains(line, "level=INFO") || !strings.Contains(line, "msg=hello") {
					t.Fatalf("text output = %q, want level=INFO and msg=hello", line)
				}
			},
		},
		{
			name: "json with debug level",
			cfg:  LogConfig{Format: LogFormatJSON, Level: "debug"},
			log:  func(l *slog.Logger) { l.Debug("hello") },
			assert: func(t *testing.T, line string) {
				t.Helper()
				var rec map[string]any
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatalf("json output %q: %v", line, err)
				}
				if rec["msg"] != "hello" {
					t.Fatalf("msg = %v, want hello", rec["msg"])
				}
				if rec["level"] != "DEBUG" {
					t.Fatalf("level = %v, want DEBUG", rec["level"])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger, err := NewLogger(&buf, tc.cfg)
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			tc.log(logger)
			tc.assert(t, strings.TrimSpace(buf.String()))
		})
	}
}

func TestNewLoggerRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  LogConfig
	}{
		{name: "unknown format", cfg: LogConfig{Format: "xml"}},
		{name: "unknown level", cfg: LogConfig{Level: "loud"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewLogger(&bytes.Buffer{}, tc.cfg); err == nil {
				t.Fatal("NewLogger returned nil error")
			}
		})
	}
}

func TestSetupLoggingInstallsDefault(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var buf bytes.Buffer
	logger, err := SetupLogging(&buf, LogConfig{Format: LogFormatJSON, Level: "debug"})
	if err != nil {
		t.Fatalf("SetupLogging: %v", err)
	}
	if slog.Default() != logger {
		t.Fatal("SetupLogging did not install its logger as slog.Default()")
	}

	slog.Info("through default")
	if !strings.Contains(buf.String(), "through default") {
		t.Fatalf("slog.Default() output = %q, want the installed handler", buf.String())
	}
}
