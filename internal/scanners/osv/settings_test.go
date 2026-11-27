package osv

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/ozerozdas/bastion/internal/findings"
)

func TestSettingsDefaultOn(t *testing.T) {
	dir := t.TempDir()
	settings := NewSettings(dir)
	if !settings.Enabled() {
		t.Fatal("a fresh install must have the OSV lookup on")
	}
	if _, err := os.Stat(filepath.Join(dir, settingsFileName)); !os.IsNotExist(err) {
		t.Fatalf("reading the setting wrote a file: %v", err)
	}

	// A literal, too, because the zero value must be usable.
	if !(&Settings{DataDir: dir}).Enabled() {
		t.Error("the zero Settings must default to on")
	}
}

func TestSettingsPersistOff(t *testing.T) {
	dir := t.TempDir()
	settings := NewSettings(dir)
	if err := settings.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if settings.Enabled() {
		t.Error("Enabled stays on after SetEnabled(false)")
	}
	if NewSettings(dir).Enabled() {
		t.Error("a reloaded setting is on, want off")
	}

	data, err := os.ReadFile(filepath.Join(dir, settingsFileName)) //nolint:gosec // G304: the test's own temporary directory
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	if string(data) != "{\"enabled\":false}\n" {
		t.Errorf("settings file = %q", data)
	}

	if err := NewSettings(dir).SetEnabled(true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if !NewSettings(dir).Enabled() {
		t.Error("a reloaded setting is off after enabling it")
	}
}

// TestSettingsCorruptFileFailsClosed proves a settings file that exists but
// cannot be parsed turns the lookup off: the user wrote a preference, and a
// damaged file must not silently re-enable a lookup they turned off.
func TestSettingsCorruptFileFailsClosed(t *testing.T) {
	tests := map[string]string{
		"invalid json": "{not json",
		"empty file":   "",
		"wrong shape":  `{"enabled": "yes"}`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, settingsFileName)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write settings: %v", err)
			}
			if NewSettings(dir).Enabled() {
				t.Error("a corrupt settings file must leave the OSV lookup off")
			}
			if (&Settings{DataDir: dir}).Enabled() {
				t.Error("the zero Settings must also fail closed on a corrupt file")
			}
		})
	}
}

func TestMatcherEnabled(t *testing.T) {
	if !New("test").Enabled() {
		t.Error("a matcher without Settings must be on")
	}
	var nilMatcher *Matcher
	if !nilMatcher.Enabled() {
		t.Error("a nil matcher must report on")
	}
	settings := NewSettings(t.TempDir())
	if err := settings.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	matcher := New("test")
	matcher.Settings = settings
	if matcher.Enabled() {
		t.Error("the matcher is on after the setting was turned off")
	}
}

func TestMatchOffSendsNoRequest(t *testing.T) {
	var hits atomic.Int32
	m := newMatcher(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "the offline matcher must not call out", http.StatusInternalServerError)
	})
	settings := NewSettings(t.TempDir())
	if err := settings.SetEnabled(false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	m.Settings = settings

	fs, err := m.Match(context.Background(), []findings.Package{{
		Ecosystem: "npm",
		Name:      "-harseurl",
		Version:   "0.0.1",
	}}, findings.Asset{ID: 1})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("got %d findings with the lookup off, want none", len(fs))
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0 with the lookup off", got)
	}
}
