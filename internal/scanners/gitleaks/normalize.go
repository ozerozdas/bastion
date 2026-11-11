package gitleaks

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/scanners"
)

// Normalize maps redacted Gitleaks findings into bastion's model. Every
// finding is a high-severity secret; the raw secret is not available here.
func (s *Scanner) Normalize(raw *scanners.RawResult, asset findings.Asset) ([]findings.Finding, []findings.Package, error) {
	found, err := decodeFindings(raw)
	if err != nil {
		return nil, nil, err
	}

	fs := make([]findings.Finding, 0, len(found))
	for _, sec := range found {
		file := findings.NormalizeLocation(raw.WorkspaceDir, sec.File)
		location := file
		if sec.Line > 0 {
			location = fmt.Sprintf("%s:%d", file, sec.Line)
		}
		f := findings.Finding{
			AssetID:    asset.ID,
			Type:       findings.TypeSecret,
			RuleID:     sec.RuleID,
			Severity:   findings.SeverityHigh,
			Title:      "Secret detected: " + sec.RuleID,
			Location:   location,
			Match:      sec.Match,
			SecretHMAC: sec.SecretHMAC,
			Scanner:    s.Name(),
		}
		f.Fingerprint = findings.Fingerprint(asset.ID, f)
		fs = append(fs, f)
	}

	findings.SortFindings(fs)
	return fs, []findings.Package{}, nil
}

// decodeFindings accepts either the typed payload set by Scan or native JSON
// (used by golden tests).
func decodeFindings(raw *scanners.RawResult) ([]Finding, error) {
	if raw == nil {
		return nil, errors.New("gitleaks: raw result is required")
	}
	if raw.Data != nil {
		found, ok := raw.Data.([]Finding)
		if !ok {
			return nil, fmt.Errorf("gitleaks: unexpected payload type %T", raw.Data)
		}
		return found, nil
	}
	var found []Finding
	if err := json.Unmarshal(raw.Raw, &found); err != nil {
		return nil, fmt.Errorf("gitleaks: decode findings: %w", err)
	}
	return found, nil
}
