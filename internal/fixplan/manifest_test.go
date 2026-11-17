package fixplan_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/fixplan"
)

func TestManifestPath(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		location  string
		want      string
		ok        bool
	}{
		{name: "npm lock", ecosystem: "npm", location: "package-lock.json:1", want: "package.json", ok: true},
		{name: "npm nested lock", ecosystem: "npm", location: "web/yarn.lock", want: "web/package.json", ok: true},
		{name: "npm pnpm", ecosystem: "npm", location: "apps/api/pnpm-lock.yaml", want: "apps/api/package.json", ok: true},
		{name: "npm manifest", ecosystem: "npm", location: "./package.json", want: "package.json", ok: true},
		{name: "go sum", ecosystem: "go", location: "go.sum:12", want: "go.mod", ok: true},
		{name: "go nested sum", ecosystem: "go", location: "svc/go.sum:3:9", want: "svc/go.mod", ok: true},
		{name: "go manifest", ecosystem: "go", location: "go.mod", want: "go.mod", ok: true},
		{name: "wrong ecosystem", ecosystem: "go", location: "package-lock.json", ok: false},
		{name: "unknown file", ecosystem: "npm", location: "src/index.ts", ok: false},
		{name: "empty", ecosystem: "npm", location: "", ok: false},
		{name: "parent directory", ecosystem: "npm", location: "../package-lock.json", ok: false},
		{name: "parent inside", ecosystem: "go", location: "a/../../go.sum", ok: false},
		{name: "absolute", ecosystem: "npm", location: "/etc/package-lock.json", ok: false},
		{name: "node_modules", ecosystem: "npm", location: "node_modules/pkg/package-lock.json", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fixplan.ManifestPath(tt.ecosystem, tt.location)
			if tt.ok {
				if err != nil || got != tt.want {
					t.Fatalf("ManifestPath(%q, %q) = %q, %v; want %q", tt.ecosystem, tt.location, got, err, tt.want)
				}
				return
			}
			if !errors.Is(err, fixplan.ErrManifestUnsupported) {
				t.Fatalf("ManifestPath(%q, %q) = %q, %v; want ErrManifestUnsupported", tt.ecosystem, tt.location, got, err)
			}
		})
	}
}

func TestEditGoModSingleLine(t *testing.T) {
	src := "module example.com/app\n\ngo 1.24\n\nrequire github.com/pkg/errors v0.9.0\n"

	got, err := fixplan.EditGoMod([]byte(src), "github.com/pkg/errors", "v0.9.1")
	if err != nil {
		t.Fatalf("EditGoMod: %v", err)
	}
	want := "module example.com/app\n\ngo 1.24\n\nrequire github.com/pkg/errors v0.9.1\n"
	if string(got) != want {
		t.Fatalf("EditGoMod =\n%q\nwant\n%q", got, want)
	}
}

func TestEditGoModBlock(t *testing.T) {
	src := "module example.com/app\n\nrequire (\n" +
		"\tgithub.com/a/b v1.0.0 // indirect\n" +
		"\tgithub.com/c/d v2.3.4\n" +
		")\n"

	got, err := fixplan.EditGoMod([]byte(src), "github.com/a/b", "1.0.1")
	if err != nil {
		t.Fatalf("EditGoMod: %v", err)
	}
	if !strings.Contains(string(got), "\tgithub.com/a/b v1.0.1 // indirect\n") {
		t.Fatalf("block entry not bumped in place: %q", got)
	}
	if !strings.Contains(string(got), "\tgithub.com/c/d v2.3.4\n") {
		t.Fatalf("unrelated module changed: %q", got)
	}
}

func TestEditGoModNotFound(t *testing.T) {
	src := "module example.com/app\n\nrequire github.com/a/b v1.0.0\n"
	_, err := fixplan.EditGoMod([]byte(src), "github.com/only/in/sum", "v1.0.1")
	if !errors.Is(err, fixplan.ErrManifestNotFound) {
		t.Fatalf("err = %v, want ErrManifestNotFound", err)
	}
}

func TestEditGoModIgnoresReplace(t *testing.T) {
	src := "module example.com/app\n\nrequire github.com/a/b v1.0.0\n\nreplace github.com/a/b => ../b\n"
	got, err := fixplan.EditGoMod([]byte(src), "github.com/a/b", "v1.0.1")
	if err != nil {
		t.Fatalf("EditGoMod: %v", err)
	}
	if !strings.HasSuffix(string(got), "replace github.com/a/b => ../b\n") {
		t.Fatalf("replace line changed: %q", got)
	}
}

func TestEditPackageJSON(t *testing.T) {
	src := `{
    "name": "app",
    "dependencies": {
        "lodash": "^4.17.0",
        "left-pad": "1.3.0"
    },
    "devDependencies": {
        "@types/node": "~20.1.0"
    },
    "overrides": {
        "lodash": "^3.0.0"
    }
}
`

	got, err := fixplan.EditPackageJSON([]byte(src), "lodash", "4.17.21")
	if err != nil {
		t.Fatalf("EditPackageJSON: %v", err)
	}
	if !strings.Contains(string(got), `"lodash": "^4.17.21"`) {
		t.Fatalf("caret range not preserved: %q", got)
	}
	if !strings.Contains(string(got), `"left-pad": "1.3.0"`) {
		t.Fatalf("pinned entry changed: %q", got)
	}
	if !strings.Contains(string(got), `"overrides": {
        "lodash": "^3.0.0"
    }`) {
		t.Fatalf("an entry outside the dependency sections changed: %q", got)
	}
	if !strings.HasSuffix(string(got), "\n}\n") {
		t.Fatalf("trailing newline or indentation changed: %q", got)
	}
}

func TestEditPackageJSONRangePrefixes(t *testing.T) {
	tests := []struct {
		name    string
		current string
		want    string
	}{
		{name: "caret", current: "^1.2.3", want: "^2.0.0"},
		{name: "tilde", current: "~1.2.3", want: "~2.0.0"},
		{name: "exact", current: "1.2.3", want: "2.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := `{"dependencies":{"pkg":"` + tt.current + `"}}`
			got, err := fixplan.EditPackageJSON([]byte(src), "pkg", "2.0.0")
			if err != nil {
				t.Fatalf("EditPackageJSON: %v", err)
			}
			if want := `{"dependencies":{"pkg":"` + tt.want + `"}}`; string(got) != want {
				t.Fatalf("EditPackageJSON = %q, want %q", got, want)
			}
		})
	}
}

func TestEditPackageJSONNotFound(t *testing.T) {
	src := `{"dependencies":{"lodash":"^4.17.0"}}`
	_, err := fixplan.EditPackageJSON([]byte(src), "transitive-only", "1.0.0")
	if !errors.Is(err, fixplan.ErrManifestNotFound) {
		t.Fatalf("err = %v, want ErrManifestNotFound", err)
	}
}

func TestEditPackageJSONInvalidJSON(t *testing.T) {
	_, err := fixplan.EditPackageJSON([]byte(`{"dependencies":`), "pkg", "1.0.0")
	if !errors.Is(err, fixplan.ErrManifestUnsupported) {
		t.Fatalf("err = %v, want ErrManifestUnsupported", err)
	}
}

func TestEditPackageJSONUnsupportedRange(t *testing.T) {
	src := `{"dependencies":{"pkg":"workspace:*"}}`
	_, err := fixplan.EditPackageJSON([]byte(src), "pkg", "1.0.0")
	if !errors.Is(err, fixplan.ErrManifestUnsupported) {
		t.Fatalf("err = %v, want ErrManifestUnsupported", err)
	}
}
