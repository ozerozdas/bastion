package gitleaks

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/detect"
)

// TestDefaultConfigLoadsRules guards the local-Viper config path: if the
// embedded TOML stops parsing, ScanDir silently produces no findings.
func TestDefaultConfigLoadsRules(t *testing.T) {
	cfg, err := defaultConfig()
	if err != nil {
		t.Fatalf("defaultConfig: %v", err)
	}
	if len(cfg.Rules) == 0 || len(cfg.Keywords) == 0 {
		t.Fatalf("default config is incomplete: %d rules, %d keywords", len(cfg.Rules), len(cfg.Keywords))
	}
	if _, ok := cfg.Rules["aws-access-token"]; !ok {
		t.Fatalf("aws-access-token rule missing (%d rules loaded)", len(cfg.Rules))
	}

	// The AWS rule matches AKIA plus 16 characters from [A-Z2-7].
	secret := "AKIA" + "Q7W3ZR5M4N2P6T3V"
	findings := detect.NewDetector(cfg).DetectString("aws_access_key_id = " + secret + "\n")
	if len(findings) == 0 {
		t.Fatal("DetectString found no aws-access-token")
	}
}
