package aws

import (
	"errors"
	"strings"
	"testing"
)

// apiError stands in for a smithy API error, which exposes only its code.
type apiError struct{ code string }

func (e apiError) Error() string     { return "operation error: " + e.code }
func (e apiError) ErrorCode() string { return e.code }

func TestNewRequiresRegion(t *testing.T) {
	if _, err := New(Config{Profile: "default"}); err == nil {
		t.Fatal("New accepted a client without a region")
	}
	client, err := New(Config{Region: "eu-central-1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.version != "dev" {
		t.Errorf("version = %q, want dev", client.version)
	}
}

// TestLoadOptionsForceProfileOnlyWhenSet: an empty profile keeps the SDK's
// normal precedence, a named one is passed through.
func TestLoadOptionsForceProfileOnlyWhenSet(t *testing.T) {
	without, err := New(Config{Region: "eu-central-1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := len(without.loadOptions()); got != 2 {
		t.Errorf("load options without profile = %d, want 2", got)
	}

	with, err := New(Config{Profile: "work", Region: "eu-central-1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := len(with.loadOptions()); got != 3 {
		t.Errorf("load options with profile = %d, want 3", got)
	}
}

// TestCallHint: each API code names the part of the setup to fix.
func TestCallHint(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		profile string
		want    string
	}{
		{
			name: "expired token",
			err:  apiError{code: "ExpiredToken"},
			want: "AWS rejected the credentials (ExpiredToken); refresh the AWS session and test again",
		},
		{
			name: "access denied",
			err:  apiError{code: "AccessDenied"},
			want: "AWS denied sts:GetCallerIdentity (AccessDenied); check the profile's permissions",
		},
		{
			name: "other code",
			err:  apiError{code: "Throttling"},
			want: "AWS returned Throttling",
		},
		{
			name:    "credentials chain",
			err:     errors.New("failed to refresh cached credentials, no EC2 IMDS role found"),
			profile: "work",
			want:    "no usable credentials for profile \"work\"; run `aws sso login --profile work` or configure keys for it",
		},
		{
			name: "network",
			err:  errors.New("dial tcp: i/o timeout"),
			want: "could not reach AWS; check the network and the profile",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := callHint(tt.err, tt.profile); got != tt.want {
				t.Errorf("callHint = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestConfigHint: a missing profile is the common case and names the file.
func TestConfigHint(t *testing.T) {
	err := errors.New("failed to get shared config profile, work")
	got := configHint(err, "work")
	if !strings.Contains(got, `profile "work"`) {
		t.Errorf("configHint = %q, want the profile name", got)
	}
}
