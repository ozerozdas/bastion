package assets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/store"
)

// TestSetFindingStatesValidatesBatch covers the checks that run before the
// database, including the batch cap, so a zero-value Service is enough.
func TestSetFindingStatesValidatesBatch(t *testing.T) {
	overCap := make([]string, store.MaxFindingStateBatch+1)
	for i := range overCap {
		overCap[i] = fmt.Sprintf("fp-%d", i)
	}

	cases := []struct {
		name string
		in   BulkFindingStateInput
		want string
	}{
		{
			name: "no fingerprints",
			in: BulkFindingStateInput{
				AssetID: 1, State: store.FindingStateIgnored, Reason: "r",
			},
			want: "at least one fingerprint",
		},
		{
			name: "over the cap",
			in: BulkFindingStateInput{
				AssetID: 1, Fingerprints: overCap, State: store.FindingStateIgnored, Reason: "r",
			},
			want: "at most 5000",
		},
		{
			name: "blank fingerprint",
			in: BulkFindingStateInput{
				AssetID: 1, Fingerprints: []string{"fp-1", " "}, State: store.FindingStateIgnored, Reason: "r",
			},
			want: "fingerprint is required",
		},
		{
			name: "blank reason",
			in: BulkFindingStateInput{
				AssetID: 1, Fingerprints: []string{"fp-1"}, State: store.FindingStateIgnored, Reason: " ",
			},
			want: "a reason is required",
		},
		{
			name: "unknown state",
			in: BulkFindingStateInput{
				AssetID: 1, Fingerprints: []string{"fp-1"}, State: "muted", Reason: "r",
			},
			want: `state "muted" is not one of`,
		},
		{
			name: "missing asset id",
			in: BulkFindingStateInput{
				Fingerprints: []string{"fp-1"}, State: store.FindingStateIgnored, Reason: "r",
			},
			want: "asset_id must be positive",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (&Service{}).SetFindingStates(context.Background(), tc.in)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("SetFindingStates = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestValidateImageRef(t *testing.T) {
	valid := []string{
		"nginx:latest",
		"ghcr.io/ozerozdas/bastion:v1.2.3",
		"registry.example.com:5000/team/app@sha256:abcdef",
		"my_image-1.0",
	}
	for _, ref := range valid {
		if err := validateImageRef(ref); err != nil {
			t.Errorf("validateImageRef(%q) = %v, want nil", ref, err)
		}
	}

	invalid := []string{
		"",
		"-nginx:latest",
		"nginx latest",
		"nginx;rm -rf /",
		"nginx#latest",
		"nginx\nlatest",
	}
	for _, ref := range invalid {
		err := validateImageRef(ref)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("validateImageRef(%q) = %v, want ErrInvalid", ref, err)
		}
	}
}
