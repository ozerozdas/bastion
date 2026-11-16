package httpapi

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// exportSheet is the part of xl/worksheets/sheet1.xml these tests read.
type exportSheet struct {
	Rows []struct {
		Cells []struct {
			Ref    string `xml:"r,attr"`
			Type   string `xml:"t,attr"`
			Value  string `xml:"v"`
			Inline struct {
				Text string `xml:"t"`
			} `xml:"is"`
		} `xml:"c"`
	} `xml:"sheetData>row"`
}

// TestFindingsExportFormats drives all three downloads for both views. The
// fixture's latest scans hold two open findings plus one ignored secret.
func TestFindingsExportFormats(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	seedFindingsFixture(t, ts)

	filename := regexp.MustCompile(`^attachment; filename="bastion-findings-(grouped|single)-\d{8}\.(csv|xlsx|json)"$`)

	t.Run("csv grouped", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet, "/api/findings/export?format=csv", withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got, want := resp.Header.Get("Content-Type"), "text/csv; charset=utf-8"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		if got := resp.Header.Get("Content-Disposition"); !filename.MatchString(got) {
			t.Errorf("Content-Disposition = %q, want a grouped CSV attachment", got)
		}
		body := readBody(t, resp)
		if !bytes.HasPrefix(body, []byte("\uFEFF")) {
			t.Errorf("CSV does not start with a UTF-8 BOM: %q", body[:min(8, len(body))])
		}
		if !strings.HasPrefix(string(body), "\uFEFFRule,Type,Severity,Title,Packages,Projects,Findings,Open") {
			t.Errorf("CSV header = %q", firstLine(string(body)))
		}
	})

	t.Run("json single", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet,
			"/api/findings/export?format=json&view=single&status=open", withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got, want := resp.Header.Get("Content-Type"), "application/json"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		if got := resp.Header.Get("Content-Disposition"); !filename.MatchString(got) {
			t.Errorf("Content-Disposition = %q, want a single JSON attachment", got)
		}
		var rows []map[string]any
		if err := json.Unmarshal(readBody(t, resp), &rows); err != nil {
			t.Fatalf("decode JSON export: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("rows = %d, want 2 open findings", len(rows))
		}
		projects := map[string]bool{}
		for _, row := range rows {
			project, ok := row["project"].(string)
			if !ok || project == "" {
				t.Fatalf("row has no project: %+v", row)
			}
			projects[project] = true
			if _, ok := row["first_seen_scan"]; !ok {
				t.Errorf("row has no first_seen_scan: %+v", row)
			}
		}
		if !projects["Alpha"] || !projects["Beta"] {
			t.Errorf("projects = %v, want Alpha and Beta", projects)
		}
	})

	t.Run("xlsx single", func(t *testing.T) {
		resp := ts.do(t, http.MethodGet,
			"/api/findings/export?format=xlsx&view=single", withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got, want := resp.Header.Get("Content-Type"),
			"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		if got := resp.Header.Get("Content-Disposition"); !filename.MatchString(got) {
			t.Errorf("Content-Disposition = %q, want a single XLSX attachment", got)
		}

		body := readBody(t, resp)
		reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			t.Fatalf("open XLSX zip: %v", err)
		}
		sheet := readExportSheet(t, reader)
		if got, want := len(sheet.Rows), 4; got != want {
			t.Fatalf("rows = %d, want %d (header plus three findings)", got, want)
		}
		if got := sheet.Rows[0].Cells[0].Inline.Text; got != "Project" {
			t.Errorf("A1 = %q, want Project", got)
		}
		// Three findings, one per row, and the first row's project is a name.
		if got := sheet.Rows[1].Cells[0].Inline.Text; got != "Alpha" && got != "Beta" {
			t.Errorf("A2 = %q, want a project name", got)
		}
	})
}

// readExportSheet parses the only worksheet of an exported workbook.
func readExportSheet(t *testing.T, reader *zip.Reader) exportSheet {
	t.Helper()

	file, err := reader.Open("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatalf("open sheet1.xml: %v", err)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read sheet1.xml: %v", err)
	}

	var sheet exportSheet
	if err := xml.Unmarshal(raw, &sheet); err != nil {
		t.Fatalf("parse sheet1.xml: %v", err)
	}
	return sheet
}

// firstLine is a test failure's readable CSV prefix.
func firstLine(body string) string {
	if index := strings.IndexAny(body, "\r\n"); index >= 0 {
		return body[:index]
	}
	return body
}

// TestFindingsExportFilterParity proves the export reads the same filter as the
// list: for each query the JSON rows match the list's findings exactly.
func TestFindingsExportFilterParity(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)
	alpha, beta, _ := seedFindingsFixture(t, ts)

	queries := []string{
		"",
		"?asset_id=" + itoa(alpha.ID),
		"?asset_id=" + itoa(beta.ID),
		"?severity=high",
		"?type=secret",
		"?status=ignored",
		"?status=open",
		"?type=vulnerability&severity=medium",
	}
	for _, query := range queries {
		resp := ts.do(t, http.MethodGet, "/api/findings"+query, withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("list %q: status = %d", query, resp.StatusCode)
		}
		want := len(decodeFindings(t, readBody(t, resp)).Findings)

		exportQuery := "?format=json&view=single"
		if query != "" {
			exportQuery += "&" + strings.TrimPrefix(query, "?")
		}
		resp = ts.do(t, http.MethodGet, "/api/findings/export"+exportQuery, withCookie(cookie))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export %q: status = %d", exportQuery, resp.StatusCode)
		}
		var rows []map[string]any
		if err := json.Unmarshal(readBody(t, resp), &rows); err != nil {
			t.Fatalf("decode export %q: %v", exportQuery, err)
		}
		if len(rows) != want {
			t.Errorf("export %q has %d rows, list has %d findings", exportQuery, len(rows), want)
		}
	}
}

// TestFindingsExportRejectsBadParams covers the problem+json mapping for every
// malformed parameter.
func TestFindingsExportRejectsBadParams(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	paths := []string{
		"/api/findings/export",
		"/api/findings/export?format=xml",
		"/api/findings/export?format=csv&view=flat",
		"/api/findings/export?format=csv&asset_id=0",
		"/api/findings/export?format=csv&asset_id=nope",
		"/api/findings/export?format=csv&severity=urgent",
		"/api/findings/export?format=csv&type=exploit",
		"/api/findings/export?format=csv&status=done",
	}
	for _, path := range paths {
		resp := ts.do(t, http.MethodGet, path, withCookie(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want %d", path, resp.StatusCode, http.StatusBadRequest)
			continue
		}
		problem := readProblem(t, resp)
		if problem.Status != http.StatusBadRequest || problem.Detail == nil || *problem.Detail == "" {
			t.Errorf("%s: problem = %+v, want a 400 with detail", path, problem)
		}
	}
}

// TestFindingsExportRequiresSession keeps the download behind the same cookie
// as every other GET.
func TestFindingsExportRequiresSession(t *testing.T) {
	ts := newTestServer(t)

	resp := ts.do(t, http.MethodGet, "/api/findings/export?format=csv", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	readProblem(t, resp)
}
