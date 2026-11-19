package reports

import (
	"context"
	"strconv"

	"github.com/ozerozdas/bastion/internal/findings"
)

// OWASPUnmapped is the id of the bucket that holds findings whose CWE ids are
// absent or outside the OWASP Top 10 2021 mapping. It is always the last
// category of the report.
const OWASPUnmapped = "unmapped"

// OWASPCategory is one OWASP Top 10 2021 category (or the unmapped bucket) and
// the latest open findings that belong to it.
type OWASPCategory struct {
	ID       string
	Title    string
	Count    int
	Findings []Finding
}

// owaspCategory is one row of the report's fixed category list.
type owaspCategory struct {
	id    string
	title string
	// cwes are the CWE numbers the official 2021 mapping lists under this
	// category. The list is ordered A01 to A10, so the first category that
	// claims a CWE wins when a CWE appears twice.
	cwes []int
}

// owaspCategories is the OWASP Top 10 2021 list, in order. Titles are English
// and mirror the official names.
var owaspCategories = []owaspCategory{
	{
		id:    "A01",
		title: "A01:2021 - Broken Access Control",
		cwes: []int{
			22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359,
			377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651,
			668, 706, 862, 863, 913, 922, 1270, 1275, 1345, 1390,
		},
	},
	{
		id:    "A02",
		title: "A02:2021 - Cryptographic Failures",
		cwes: []int{
			261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329,
			330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760,
			818, 916,
		},
	},
	{
		id:    "A03",
		title: "A03:2021 - Injection",
		cwes: []int{
			20, 74, 75, 77, 78, 79, 80, 83, 86, 87, 88, 89, 90, 91, 93, 94,
			95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 564, 610, 643,
			644, 652, 917,
		},
	},
	{
		id:    "A04",
		title: "A04:2021 - Insecure Design",
		cwes: []int{
			73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313,
			316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598,
			602, 642, 646, 653, 656, 657, 799, 807, 840, 841, 927, 1021,
			1173,
		},
	},
	{
		id:    "A05",
		title: "A05:2021 - Security Misconfiguration",
		cwes: []int{
			2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 612,
			613, 614, 756, 776, 942, 1004, 1032, 1174,
		},
	},
	{
		id:    "A06",
		title: "A06:2021 - Vulnerable and Outdated Components",
		cwes:  []int{937, 1035, 1104},
	},
	{
		id:    "A07",
		title: "A07:2021 - Identification and Authentication Failures",
		cwes: []int{
			255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307,
			346, 384, 521, 620, 640, 798, 940, 1216,
		},
	},
	{
		id:    "A08",
		title: "A08:2021 - Software and Data Integrity Failures",
		cwes:  []int{345, 353, 426, 494, 502, 565, 784, 829, 830, 915, 926},
	},
	{
		id:    "A09",
		title: "A09:2021 - Security Logging and Monitoring Failures",
		cwes:  []int{117, 223, 532, 778},
	},
	{
		id:    "A10",
		title: "A10:2021 - Server-Side Request Forgery (SSRF)",
		cwes:  []int{918},
	},
}

// cweOWASP maps a canonical "CWE-<n>" id to its 2021 category. CWE-613 is
// listed under both A05 and A07; the lowest A-number (A05) wins, which is also
// how a finding with several mapped weaknesses picks one.
var cweOWASP = func() map[string]string {
	mapping := make(map[string]string)
	for _, category := range owaspCategories {
		for _, number := range category.cwes {
			id := "CWE-" + strconv.Itoa(number)
			if _, exists := mapping[id]; !exists {
				mapping[id] = category.id
			}
		}
	}
	return mapping
}()

// OWASPCategoryFor returns the category a finding's CWE ids map to: the
// lowest-numbered category any of them maps to, or OWASPUnmapped when none
// does. The result is always one of the report's ids.
func OWASPCategoryFor(cweIDs []string) string {
	category := OWASPUnmapped
	for _, id := range cweIDs {
		mapped, ok := cweOWASP[id]
		if !ok {
			continue
		}
		if category == OWASPUnmapped || mapped < category {
			category = mapped
		}
	}
	return category
}

// OWASPTop10 groups the latest open findings of the given asset (0 means every
// asset) by OWASP Top 10 2021 category. The scope is the latest findings list's:
// the newest succeeded scan of every non-archived asset, with ignored findings
// left out. Only vulnerability, SAST, misconfiguration and secret findings are
// reported; maintenance findings (outdated, licence, malware) carry no
// weakness. Every category is present in order, and unmapped is last.
func (s *Service) OWASPTop10(ctx context.Context, assetID int64) ([]OWASPCategory, error) {
	filter := Filter{AssetID: assetID, Status: FindingStatusOpen}
	if err := filter.validate(); err != nil {
		return nil, err
	}
	list, err := s.Findings(ctx, filter)
	if err != nil {
		return nil, err
	}

	categories := make([]OWASPCategory, 0, len(owaspCategories)+1)
	position := make(map[string]int, len(owaspCategories)+1)
	for _, category := range owaspCategories {
		position[category.id] = len(categories)
		categories = append(categories, OWASPCategory{
			ID:       category.id,
			Title:    category.title,
			Findings: make([]Finding, 0),
		})
	}
	position[OWASPUnmapped] = len(categories)
	categories = append(categories, OWASPCategory{
		ID:       OWASPUnmapped,
		Title:    "Unmapped",
		Findings: make([]Finding, 0),
	})

	for _, finding := range list {
		if !owaspRelevant(finding.Type) {
			continue
		}
		index := position[OWASPCategoryFor(finding.CWE)]
		categories[index].Findings = append(categories[index].Findings, finding)
		categories[index].Count++
	}
	return categories, nil
}

// owaspRelevant reports whether a finding type can carry a weakness: a
// dependency, licence or malware finding maps to no OWASP category.
func owaspRelevant(kind string) bool {
	switch findings.Type(kind) {
	case findings.TypeVulnerability, findings.TypeSAST, findings.TypeMisconfig, findings.TypeSecret:
		return true
	}
	return false
}
