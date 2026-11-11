package gitleaks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

	findings, err := ScanDir(context.Background(), dir, testKey, nil)
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
	if _, err := ScanDir(context.Background(), t.TempDir(), nil, nil); err == nil {
		t.Fatal("ScanDir accepted an empty HMAC key")
	}
}

func TestScanDirRejectsFileTarget(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := ScanDir(context.Background(), file, testKey, nil); err == nil {
		t.Fatal("ScanDir accepted a file target")
	}
}

// TestScanDirSkipsDirs proves a secret under a skipped directory (named
// relative to the scan root) never reaches the result, while the same secret
// outside it is still reported.
func TestScanDirSkipsDirs(t *testing.T) {
	dir := t.TempDir()
	// Assembled here so the repository never contains a secret-shaped string.
	body := "aws_access_key_id = " + "AKIA" + "Q7W3ZR5M4N2P6T3V" + "\n"
	for _, rel := range []string{"config/credentials", "testdata/fixture/credentials"} {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	all, err := ScanDir(context.Background(), dir, testKey, nil)
	if err != nil {
		t.Fatalf("ScanDir without skip dirs: %v", err)
	}
	if got, want := scannedFiles(all), []string{"config/credentials", "testdata/fixture/credentials"}; !slices.Equal(got, want) {
		t.Fatalf("scanned files = %v, want %v", got, want)
	}

	kept, err := ScanDir(context.Background(), dir, testKey, []string{"testdata"})
	if err != nil {
		t.Fatalf("ScanDir with skip dirs: %v", err)
	}
	if got, want := scannedFiles(kept), []string{"config/credentials"}; !slices.Equal(got, want) {
		t.Fatalf("scanned files with --skip-dirs testdata = %v, want %v", got, want)
	}

	if _, err := ScanDir(context.Background(), dir, testKey, []string{dir}); err == nil {
		t.Fatal("ScanDir accepted an absolute skip dir")
	}
	if _, err := ScanDir(context.Background(), dir, testKey, []string{"../up"}); err == nil {
		t.Fatal("ScanDir accepted a skip dir outside the scan root")
	}
}

// scannedFiles lists the distinct files the findings point at, sorted.
func scannedFiles(findings []Finding) []string {
	var files []string
	for _, f := range findings {
		if !slices.Contains(files, f.File) {
			files = append(files, f.File)
		}
	}
	slices.Sort(files)
	return files
}

func TestRedactMatch(t *testing.T) {
	tests := map[string]string{
		"AKIAQ7W3ZR5M4N2P6T3V": "AKIA****", // gitleaks:allow (fake test key)
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
