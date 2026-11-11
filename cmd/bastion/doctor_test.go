package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/app"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store"
)

// testDoctorDeps returns production code paths with the keyring faked out. The
// database is a real SQLite file in a temp dir; the keyring never runs.
func testDoctorDeps(t *testing.T) doctorDeps {
	t.Helper()

	dir := t.TempDir()
	return doctorDeps{
		bastionVersion:  "test",
		goVersion:       "go1.27.0",
		goos:            "darwin",
		goarch:          "arm64",
		paths:           app.Paths{DataDir: dir, CacheDir: filepath.Join(dir, "cache")},
		openDB:          store.Open,
		schemaVersion:   store.MigrationVersion,
		closeDB:         (*sql.DB).Close,
		trivyVersion:    "0.76.2",
		gitleaksVersion: "8.30.1",
		keyringAvailable: func() error {
			return nil
		},
		secretStore: secrets.NewMemoryStore(),
		getenv:      func(string) string { return "" },
	}
}

func TestRunDoctorHealthy(t *testing.T) {
	deps := testDoctorDeps(t)

	report, err := runDoctor(context.Background(), deps)
	if err != nil {
		t.Fatalf("runDoctor: %v", err)
	}

	if report.Database.Status != "ok" {
		t.Fatalf("database status = %q, want ok", report.Database.Status)
	}
	if report.Database.SchemaVersion != 1 {
		t.Fatalf("schema version = %d, want 1", report.Database.SchemaVersion)
	}
	if report.Keyring.Status != "ok" {
		t.Fatalf("keyring = %+v, want ok", report.Keyring)
	}
	if report.HMACKey.Status != "missing" {
		t.Fatalf("hmac key = %+v, want missing on a fresh install", report.HMACKey)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", report.Warnings)
	}
	if _, err := os.Stat(deps.paths.DBPath()); err != nil {
		t.Fatalf("database file was not created: %v", err)
	}
}

func TestRunDoctorReportsHMACKeySourceWithoutLeakingIt(t *testing.T) {
	const hmacFixtureValue = "do-not-print-this-key" // gosec G101: a fixture that must never be printed

	t.Run("keyring", func(t *testing.T) {
		deps := testDoctorDeps(t)
		if err := deps.secretStore.Set(secrets.HMACKeyName, hmacFixtureValue); err != nil {
			t.Fatalf("seed keyring fake: %v", err)
		}

		report, err := runDoctor(context.Background(), deps)
		if err != nil {
			t.Fatalf("runDoctor: %v", err)
		}
		if report.HMACKey.Status != "keyring" {
			t.Fatalf("hmac key = %+v, want keyring", report.HMACKey)
		}
		assertOutputOmits(t, report, hmacFixtureValue)
	})

	t.Run("env", func(t *testing.T) {
		deps := testDoctorDeps(t)
		deps.getenv = func(name string) string {
			if name == secrets.EnvHMACKey {
				return hmacFixtureValue
			}
			return ""
		}

		report, err := runDoctor(context.Background(), deps)
		if err != nil {
			t.Fatalf("runDoctor: %v", err)
		}
		if report.HMACKey.Status != "env" {
			t.Fatalf("hmac key = %+v, want env", report.HMACKey)
		}
		assertOutputOmits(t, report, hmacFixtureValue)
	})
}

// assertOutputOmits fails if either output format contains value.
func assertOutputOmits(t *testing.T, report doctorReport, value string) {
	t.Helper()

	var text bytes.Buffer
	if err := writeDoctorText(&text, report); err != nil {
		t.Fatalf("writeDoctorText: %v", err)
	}
	if strings.Contains(text.String(), value) {
		t.Fatalf("text report leaks the HMAC key value:\n%s", text.String())
	}

	var asJSON bytes.Buffer
	if err := writeDoctorJSON(&asJSON, report); err != nil {
		t.Fatalf("writeDoctorJSON: %v", err)
	}
	if strings.Contains(asJSON.String(), value) {
		t.Fatalf("JSON report leaks the HMAC key value:\n%s", asJSON.String())
	}
}

func TestRunDoctorWarnsWhenKeyringUnavailable(t *testing.T) {
	deps := testDoctorDeps(t)
	deps.keyringAvailable = func() error { return errors.New("no secret service") }

	report, err := runDoctor(context.Background(), deps)
	if err != nil {
		t.Fatalf("runDoctor returned a hard error for a degraded keyring: %v", err)
	}
	if report.Keyring.Status != "unavailable" {
		t.Fatalf("keyring = %+v, want unavailable", report.Keyring)
	}
	if len(report.Warnings) == 0 {
		t.Fatal("keyring unavailability produced no warning")
	}
	if !strings.Contains(strings.Join(report.Warnings, "\n"), "BASTION_") {
		t.Fatalf("warnings = %v, want the environment fallback hint", report.Warnings)
	}
}

func TestRunDoctorFailsOnlyWhenDatabaseCannotOpen(t *testing.T) {
	deps := testDoctorDeps(t)
	deps.openDB = func(context.Context, string) (*sql.DB, error) {
		return nil, errors.New("disk on fire")
	}

	report, err := runDoctor(context.Background(), deps)
	if err == nil {
		t.Fatal("runDoctor returned nil error for an unopenable database")
	}
	if !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("error = %v, want the underlying cause", err)
	}
	if report.Database.Status != "error" {
		t.Fatalf("database status = %q, want error", report.Database.Status)
	}
	if !strings.Contains(report.Database.Error, "disk on fire") {
		t.Fatalf("database error = %q, want the underlying cause", report.Database.Error)
	}
}

func TestWriteDoctorText(t *testing.T) {
	report := doctorReport{
		BastionVersion:  "dev",
		GoVersion:       "go1.27.0",
		OS:              "darwin",
		Arch:            "arm64",
		DataDir:         "/data",
		CacheDir:        "/cache",
		Database:        doctorDatabase{Path: "/data/bastion.db", Status: "ok", SchemaVersion: 1},
		TrivyVersion:    "0.76.2",
		GitleaksVersion: "8.30.1",
		Keyring:         doctorStatus{Status: "ok"},
		HMACKey:         doctorStatus{Status: "missing", Detail: "not created yet"},
	}

	var out bytes.Buffer
	if err := writeDoctorText(&out, report); err != nil {
		t.Fatalf("writeDoctorText: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"bastion", "dev",
		"go", "go1.27.0 darwin/arm64",
		"data dir", "/data",
		"cache dir", "/cache",
		"database", "/data/bastion.db",
		"ok (schema version 1)",
		"trivy", "0.76.2",
		"gitleaks", "8.30.1",
		"hmac key", "missing (not created yet)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("text report missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\t") {
		t.Errorf("text report still contains tab separators:\n%s", got)
	}
	if strings.Contains(got, "warning:") {
		t.Errorf("unexpected warnings section:\n%s", got)
	}
}

func TestWriteDoctorJSON(t *testing.T) {
	report := doctorReport{
		BastionVersion: "dev",
		Database:       doctorDatabase{Path: "/data/bastion.db", Status: "ok", SchemaVersion: 1},
		Keyring:        doctorStatus{Status: "unavailable", Detail: "no secret service"},
		HMACKey:        doctorStatus{Status: "missing"},
		Warnings:       []string{"keyring unavailable"},
	}

	var out bytes.Buffer
	if err := writeDoctorJSON(&out, report); err != nil {
		t.Fatalf("writeDoctorJSON: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON report: %v\n%s", err, out.String())
	}
	database, ok := decoded["database"].(map[string]any)
	if !ok {
		t.Fatalf("database field = %T, want object", decoded["database"])
	}
	if database["status"] != "ok" || database["schema_version"] != float64(1) {
		t.Fatalf("database = %v, want ok schema version 1", database)
	}
	keyring, ok := decoded["keyring"].(map[string]any)
	if !ok || keyring["status"] != "unavailable" {
		t.Fatalf("keyring = %v, want unavailable", decoded["keyring"])
	}
}
