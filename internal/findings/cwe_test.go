package findings

import (
	"slices"
	"testing"
)

func TestNormalizeCWEIDs(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		want   []string
	}{
		{
			name:   "canonical ids keep their order",
			labels: []string{"CWE-79", "CWE-89"},
			want:   []string{"CWE-79", "CWE-89"},
		},
		{
			name:   "titles after the id are dropped",
			labels: []string{"CWE-89: Improper Neutralization of Special Elements", "CWE-79: Cross-site Scripting"},
			want:   []string{"CWE-79", "CWE-89"},
		},
		{
			name:   "several ids in one string are all kept",
			labels: []string{"CWE-79: XSS, CWE-116: Encoding"},
			want:   []string{"CWE-79", "CWE-116"},
		},
		{
			name:   "duplicates collapse and case is ignored",
			labels: []string{"cwe-79", "CWE-79: Cross-site Scripting", "CWE-0079"},
			want:   []string{"CWE-79"},
		},
		{
			name:   "numeric order rather than lexicographic",
			labels: []string{"CWE-889", "CWE-79", "CWE-1000"},
			want:   []string{"CWE-79", "CWE-889", "CWE-1000"},
		},
		{
			name:   "labels without an id are dropped",
			labels: []string{"", "NVD-CWE-noinfo", "CWE-"},
			want:   nil,
		},
		{
			name:   "no labels",
			labels: nil,
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeCWEIDs(tt.labels); !slices.Equal(got, tt.want) {
				t.Fatalf("NormalizeCWEIDs(%v) = %v, want %v", tt.labels, got, tt.want)
			}
		})
	}
}
