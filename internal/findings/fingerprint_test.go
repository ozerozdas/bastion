package findings

import (
	"strings"
	"testing"
)

func baseVulnerability() Finding {
	return Finding{
		AssetID:        7,
		Type:           TypeVulnerability,
		RuleID:         "CVE-2020-8203",
		Severity:       SeverityHigh,
		PackageName:    "lodash",
		PackageVersion: "4.17.15",
		Ecosystem:      "npm",
		Location:       "package-lock.json",
	}
}

func TestFingerprintStableAcrossVersionAndProvenanceChanges(t *testing.T) {
	base := baseVulnerability()
	want := Fingerprint(base.AssetID, base)
	if len(want) != 64 {
		t.Fatalf("Fingerprint returned %d hex chars, want 64", len(want))
	}

	tests := []struct {
		name   string
		mutate func(*Finding)
	}{
		{name: "package version bump", mutate: func(f *Finding) { f.PackageVersion = "4.17.19" }},
		{name: "fixed version changes", mutate: func(f *Finding) { f.FixedVersion = "4.17.19" }},
		{name: "severity changes", mutate: func(f *Finding) { f.Severity = SeverityCritical }},
		{name: "title/description changes", mutate: func(f *Finding) {
			f.Title = "new title"
			f.Description = "new description"
		}},
		{name: "scanner name changes", mutate: func(f *Finding) { f.Scanner = "other" }},
		{name: "cvss changes", mutate: func(f *Finding) {
			score := 9.8
			f.CVSS = &score
		}},
		{name: "layer digest changes for an image finding", mutate: func(f *Finding) {
			f.LayerDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := base
			tt.mutate(&got)
			if fp := Fingerprint(got.AssetID, got); fp != want {
				t.Fatalf("fingerprint changed to %s, want %s", fp, want)
			}
		})
	}
}

func TestFingerprintChangesWhenIdentityChanges(t *testing.T) {
	base := baseVulnerability()
	want := Fingerprint(base.AssetID, base)

	tests := []struct {
		name   string
		mutate func(*Finding)
	}{
		{name: "asset", mutate: func(f *Finding) { f.AssetID = 8 }},
		{name: "type", mutate: func(f *Finding) { f.Type = TypeLicense }},
		{name: "rule", mutate: func(f *Finding) { f.RuleID = "CVE-2021-23337" }},
		{name: "ecosystem", mutate: func(f *Finding) { f.Ecosystem = "go" }},
		{name: "package name", mutate: func(f *Finding) { f.PackageName = "minimist" }},
		{name: "location", mutate: func(f *Finding) { f.Location = "other/package-lock.json" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := base
			tt.mutate(&got)
			if fp := Fingerprint(got.AssetID, got); fp == want {
				t.Fatalf("fingerprint %s did not change", fp)
			}
		})
	}
}

func TestFingerprintSecretIgnoresLineButUsesRuleAndHMAC(t *testing.T) {
	base := Finding{
		AssetID:    7,
		Type:       TypeSecret,
		RuleID:     "aws-access-token",
		Severity:   SeverityHigh,
		Location:   "config/credentials:1",
		SecretHMAC: strings.Repeat("a", 64),
	}
	want := Fingerprint(base.AssetID, base)

	moved := base
	moved.Location = "config/credentials:942"
	if fp := Fingerprint(moved.AssetID, moved); fp != want {
		t.Fatal("moving a secret to another line changed its fingerprint")
	}

	otherRule := base
	otherRule.RuleID = "github-pat"
	if fp := Fingerprint(otherRule.AssetID, otherRule); fp == want {
		t.Fatal("changing the secret rule did not change its fingerprint")
	}

	otherSecret := base
	otherSecret.SecretHMAC = strings.Repeat("b", 64)
	if fp := Fingerprint(otherSecret.AssetID, otherSecret); fp == want {
		t.Fatal("changing the secret HMAC did not change its fingerprint")
	}
}

func TestFingerprintMisconfigIgnoresLine(t *testing.T) {
	base := Finding{
		AssetID:  7,
		Type:     TypeMisconfig,
		RuleID:   "DS-0002",
		Location: "Dockerfile#general",
	}
	want := Fingerprint(base.AssetID, base)

	shifted := base
	shifted.Location = "Dockerfile#general"
	if fp := Fingerprint(shifted.AssetID, shifted); fp != want {
		t.Fatal("misconfiguration fingerprint is not stable")
	}

	otherCause := base
	otherCause.Location = "Dockerfile#stage-build"
	if fp := Fingerprint(otherCause.AssetID, otherCause); fp == want {
		t.Fatal("a different cause identifier did not change the fingerprint")
	}
}

func TestFingerprintWorkspacePrefixIsStripped(t *testing.T) {
	first := NormalizeLocation("/tmp/bastion-ws-abc123", "/tmp/bastion-ws-abc123/pkg/package.json")
	second := NormalizeLocation("/private/var/tmp/bastion-ws-xyz789/", "/private/var/tmp/bastion-ws-xyz789/pkg/package.json")
	if first != "pkg/package.json" || second != "pkg/package.json" {
		t.Fatalf("normalized locations = %q, %q; want pkg/package.json", first, second)
	}

	a := Finding{AssetID: 1, Type: TypeVulnerability, RuleID: "CVE-1", PackageName: "x", Ecosystem: "npm", Location: first}
	b := a
	b.Location = second
	if Fingerprint(a.AssetID, a) != Fingerprint(b.AssetID, b) {
		t.Fatal("different workspace temp prefixes changed the fingerprint")
	}
}

func TestNormalizeLocation(t *testing.T) {
	tests := []struct {
		name      string
		workspace string
		location  string
		want      string
	}{
		{name: "empty", location: "", want: ""},
		{name: "relative", workspace: "/w", location: "./pkg/../pkg/a.json", want: "pkg/a.json"},
		{name: "under workspace", workspace: "/w/ws", location: "/w/ws/pkg/a.json", want: "pkg/a.json"},
		{name: "workspace itself", workspace: "/w/ws", location: "/w/ws", want: ""},
		{name: "different root", workspace: "/w/ws", location: "/other/pkg/a.json", want: "/other/pkg/a.json"},
		{name: "no workspace", location: "/w/ws/pkg/a.json", want: "/w/ws/pkg/a.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeLocation(tt.workspace, tt.location); got != tt.want {
				t.Fatalf("NormalizeLocation(%q, %q) = %q, want %q", tt.workspace, tt.location, got, tt.want)
			}
		})
	}
}
