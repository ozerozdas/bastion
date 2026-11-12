package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/httpapi"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store"
	"github.com/ozerozdas/bastion/internal/update"
)

func TestWriteUpdateNotice(t *testing.T) {
	const (
		command = "brew upgrade ozerozdas/tap/bastion"
		release = "https://github.com/ozerozdas/bastion/releases/tag/v0.1.2"
	)

	tests := []struct {
		name       string
		status     update.Status
		wantOutput []string
		wantEmpty  bool
	}{
		{
			name:      "disabled stays silent",
			status:    update.Status{Consent: update.ConsentOn, Disabled: "CI environment"},
			wantEmpty: true,
		},
		{
			name:       "unset explains how to turn it on",
			status:     update.Status{Consent: update.ConsentUnset},
			wantOutput: []string{"Release checks are off", "bastion UI", "BASTION_NO_UPDATE_CHECK=1"},
		},
		{
			name:      "off stays silent",
			status:    update.Status{Consent: update.ConsentOff},
			wantEmpty: true,
		},
		{
			name:      "up to date stays silent",
			status:    update.Status{Consent: update.ConsentOn, Current: "v0.1.1", Latest: "v0.1.1"},
			wantEmpty: true,
		},
		{
			name: "update prints the command",
			status: update.Status{
				Consent:         update.ConsentOn,
				Current:         "0.1.0",
				Latest:          "v0.1.2",
				UpdateAvailable: true,
				Command:         command,
				ReleaseURL:      release,
			},
			wantOutput: []string{
				"bastion v0.1.2 is available", "you have v0.1.0",
				command, release,
			},
		},
		{
			name: "update without a command still links the release",
			status: update.Status{
				Consent:         update.ConsentOn,
				Current:         "v0.1.0",
				Latest:          "v0.1.2",
				UpdateAvailable: true,
				ReleaseURL:      release,
			},
			wantOutput: []string{"bastion v0.1.2 is available", release},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			writeUpdateNotice(&out, tc.status)

			if tc.wantEmpty {
				if out.Len() != 0 {
					t.Fatalf("notice = %q, want no output", out.String())
				}
				return
			}
			for _, want := range tc.wantOutput {
				if !strings.Contains(out.String(), want) {
					t.Errorf("notice missing %q:\n%s", want, out.String())
				}
			}
		})
	}
}

// TestRunServePrintsConsentHint drives the real runServe path with an unset
// consent, so the notice is on stderr and no request can be made.
func TestRunServePrintsConsentHint(t *testing.T) {
	previous := version
	version = "v0.1.0"
	t.Cleanup(func() { version = previous })

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	deps := serveDeps{
		listen:      httpapi.Listen,
		openBrowser: func(string) error { return nil },
		notifyContext: func(context.Context) (context.Context, context.CancelFunc) {
			return context.WithCancel(canceled)
		},
		newServer:      httpapi.New,
		openDB:         store.Open,
		newSecretStore: func() secrets.Store { return secrets.NewMemoryStore() },
	}

	var stderr bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(&stderr)

	dir := t.TempDir()
	err := runServe(cmd, &serveOptions{
		noBrowser: true,
		paths:     app.Paths{DataDir: dir, CacheDir: dir},
	}, deps)
	if err != nil {
		t.Fatalf("runServe: %v", err)
	}

	if !strings.Contains(stderr.String(), "Release checks are off") {
		t.Fatalf("stderr has no consent hint:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "is available") {
		t.Fatalf("stderr announces an update without consent:\n%s", stderr.String())
	}
}

func TestDoctorReportsUpdateState(t *testing.T) {
	checkedAt := time.Date(2026, time.November, 12, 9, 30, 0, 0, time.UTC)

	t.Run("on with a cached release", func(t *testing.T) {
		deps := testDoctorDeps(t)
		deps.updateStatus = func() update.Status {
			return update.Status{
				Consent:   update.ConsentOn,
				Current:   "v0.1.0",
				Latest:    "v0.1.2",
				CheckedAt: checkedAt,
			}
		}

		report, err := runDoctor(context.Background(), deps)
		if err != nil {
			t.Fatalf("runDoctor: %v", err)
		}
		if report.Update.State != "on" {
			t.Errorf("update state = %q, want on", report.Update.State)
		}
		if report.Update.Latest != "v0.1.2" {
			t.Errorf("latest = %q, want v0.1.2", report.Update.Latest)
		}
		if report.Update.LastChecked != checkedAt.Format(time.RFC3339) {
			t.Errorf("last_checked = %q, want %q", report.Update.LastChecked, checkedAt.Format(time.RFC3339))
		}

		var text bytes.Buffer
		if err := writeDoctorText(&text, report); err != nil {
			t.Fatalf("writeDoctorText: %v", err)
		}
		for _, want := range []string{"update", "on, last checked 2026-11-12T09:30:00Z, latest v0.1.2"} {
			if !strings.Contains(text.String(), want) {
				t.Errorf("text report missing %q:\n%s", want, text.String())
			}
		}

		var asJSON bytes.Buffer
		if err := writeDoctorJSON(&asJSON, report); err != nil {
			t.Fatalf("writeDoctorJSON: %v", err)
		}
		var decoded struct {
			Update doctorUpdate `json:"update"`
		}
		if err := json.Unmarshal(asJSON.Bytes(), &decoded); err != nil {
			t.Fatalf("decode JSON: %v\n%s", err, asJSON.String())
		}
		if decoded.Update.State != "on" || decoded.Update.Latest != "v0.1.2" {
			t.Errorf("JSON update = %+v, want on/v0.1.2", decoded.Update)
		}
	})

	t.Run("disabled reason is reported", func(t *testing.T) {
		deps := testDoctorDeps(t)
		deps.updateStatus = func() update.Status {
			return update.Status{Consent: update.ConsentOn, Disabled: "CI environment"}
		}

		report, err := runDoctor(context.Background(), deps)
		if err != nil {
			t.Fatalf("runDoctor: %v", err)
		}
		var text bytes.Buffer
		if err := writeDoctorText(&text, report); err != nil {
			t.Fatalf("writeDoctorText: %v", err)
		}
		if !strings.Contains(text.String(), "on (disabled: CI environment)") {
			t.Errorf("text report missing the disabled reason:\n%s", text.String())
		}
	})

	t.Run("unset without a checker", func(t *testing.T) {
		deps := testDoctorDeps(t)
		report, err := runDoctor(context.Background(), deps)
		if err != nil {
			t.Fatalf("runDoctor: %v", err)
		}
		if report.Update.State != "unset" {
			t.Errorf("update state = %q, want unset", report.Update.State)
		}
	})
}
