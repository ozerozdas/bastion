package gitleaks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey is fixed so HMAC assertions are deterministic; it is not a real key.
var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestScanDirDetectsAndRedacts(t *testing.T) {
	dir := t.TempDir()

	// The fixture is generated at test time and the secret is assembled by
	// concatenation so the repository itself never contains a secret-shaped
	// string (GitHub push protection) and this file does not trip scanners.
	// The AWS rule accepts AKIA plus 16 characters from [A-Z2-7].
	secret := "AKIA" + "Q7W3ZR5M4N2P6T3V"
	body := "aws_access_key_id = " + secret + "\n"

	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "credentials"), []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	findings, err := ScanDir(context.Background(), dir, testKey)
	if err != nil {
		t.Fatalf("ScanDir: %v", err)
	}

	var found *Finding
	for i := range findings {
		if findings[i].RuleID == "aws-access-token" {
			found = &findings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("aws-access-token not detected, got %+v", findings)
	}

	if found.File != "config/credentials" {
		t.Errorf("File = %q, want config/credentials", found.File)
	}
	if found.Line != 1 {
		t.Errorf("Line = %d, want 1", found.Line)
	}
	if found.Match != "AKIA****" {
		t.Errorf("Match = %q, want AKIA****", found.Match)
	}

	mac := hmac.New(sha256.New, testKey)
	mac.Write([]byte(secret))
	if want := hex.EncodeToString(mac.Sum(nil)); found.SecretHMAC != want {
		t.Errorf("SecretHMAC = %q, want %q", found.SecretHMAC, want)
	}

	// The raw secret and the raw full line must not survive JSON encoding.
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, raw := range []string{secret, "aws_access_key_id"} {
		if strings.Contains(string(encoded), raw) {
			t.Fatalf("JSON output contains raw content %q: %s", raw, encoded)
		}
	}
}

func TestScanDirRejectsEmptyKey(t *testing.T) {
	if _, err := ScanDir(context.Background(), t.TempDir(), nil); err == nil {
		t.Fatal("ScanDir accepted an empty HMAC key")
	}
}

func TestScanDirRejectsFileTarget(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := ScanDir(context.Background(), file, testKey); err == nil {
		t.Fatal("ScanDir accepted a file target")
	}
}

func TestRedactMatch(t *testing.T) {
	tests := map[string]string{
		"AKIAQ7W3ZR5M4N2P6T3V": "AKIA****",
		"abcd":                 "****",
		"abc":                  "****",
		"":                     "****",
		"şifre-çok-gizli":      "şifr****",
	}
	for secret, want := range tests {
		if got := redactMatch(secret); got != want {
			t.Errorf("redactMatch(%q) = %q, want %q", secret, got, want)
		}
	}
}
