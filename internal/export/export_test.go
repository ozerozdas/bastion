package export

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

// testTable exercises text, numbers, commas, XML characters and every formula
// injection prefix.
func testTable() Table {
	return Table{
		Columns: []Column{
			{Key: "rule", Header: "Rule"},
			{Key: "findings", Header: "Findings"},
			{Key: "title", Header: "Title"},
		},
		Rows: [][]Cell{
			{TextCell("=SUM(A1)"), IntCell(4), TextCell("hello, world")},
			{TextCell("+1"), IntCell(0), TextCell("-2")},
			{TextCell("@cmd"), IntCell(1), TextCell("a<b>&c")},
		},
	}
}

func TestCSVGolden(t *testing.T) {
	body, err := CSV(testTable())
	if err != nil {
		t.Fatalf("CSV: %v", err)
	}

	want := "\uFEFFRule,Findings,Title\r\n" +
		"'=SUM(A1),4,\"hello, world\"\r\n" +
		"'+1,0,'-2\r\n" +
		"'@cmd,1,a<b>&c\r\n"
	if string(body) != want {
		t.Fatalf("CSV =\n%q\nwant\n%q", body, want)
	}
}

func TestCSVEmptyTableHasHeaderOnly(t *testing.T) {
	body, err := CSV(Table{Columns: []Column{{Key: "rule", Header: "Rule"}}})
	if err != nil {
		t.Fatalf("CSV: %v", err)
	}
	if got, want := string(body), "\uFEFFRule\r\n"; got != want {
		t.Fatalf("CSV = %q, want %q", got, want)
	}
}

func TestJSONShapeAndStableKeys(t *testing.T) {
	body, err := JSON(testTable())
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("decode JSON %q: %v", body, err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if got := rows[0]["rule"]; got != "=SUM(A1)" {
		t.Errorf("rule = %v, want the raw formula text", got)
	}
	if got := rows[0]["findings"]; got != float64(4) {
		t.Errorf("findings = %v, want the number 4", got)
	}

	// The key order is the column order, so a diff of two exports is stable.
	rule := bytes.Index(body, []byte(`"rule"`))
	findings := bytes.Index(body, []byte(`"findings"`))
	title := bytes.Index(body, []byte(`"title"`))
	if rule >= findings || findings >= title {
		t.Errorf("JSON keys out of column order: %q", body)
	}
}

func TestJSONEmptyTableIsArray(t *testing.T) {
	body, err := JSON(Table{Columns: []Column{{Key: "rule", Header: "Rule"}}})
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if got, want := strings.TrimSpace(string(body)), "[]"; got != want {
		t.Fatalf("JSON = %q, want %q", got, want)
	}
}

// sheet is the part of xl/worksheets/sheet1.xml these tests read.
type sheet struct {
	Rows []struct {
		Cells []struct {
			Ref    string `xml:"r,attr"`
			Type   string `xml:"t,attr"`
			Style  string `xml:"s,attr"`
			Value  string `xml:"v"`
			Inline struct {
				Text string `xml:"t"`
			} `xml:"is"`
		} `xml:"c"`
	} `xml:"sheetData>row"`
}

// readSheet opens the workbook and parses its only worksheet.
func readSheet(t *testing.T, body []byte) sheet {
	t.Helper()

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open XLSX zip: %v", err)
	}
	names := make(map[string]bool, len(reader.File))
	for _, file := range reader.File {
		names[file.Name] = true
	}
	for _, required := range []string{
		"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
		"xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/worksheets/sheet1.xml",
	} {
		if !names[required] {
			t.Fatalf("XLSX is missing %s", required)
		}
	}

	file, err := reader.Open("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatalf("open sheet1.xml: %v", err)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read sheet1.xml: %v", err)
	}

	var parsed sheet
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse sheet1.xml %q: %v", raw, err)
	}
	return parsed
}

func TestXLSXCells(t *testing.T) {
	body, err := XLSX(testTable())
	if err != nil {
		t.Fatalf("XLSX: %v", err)
	}

	parsed := readSheet(t, body)
	if len(parsed.Rows) != 4 {
		t.Fatalf("rows = %d, want 4 (header plus 3)", len(parsed.Rows))
	}

	header := parsed.Rows[0].Cells
	if len(header) != 3 {
		t.Fatalf("header cells = %d, want 3", len(header))
	}
	if header[0].Style != "1" || header[0].Inline.Text != "Rule" {
		t.Errorf("header A1 = %+v, want bold \"Rule\"", header[0])
	}

	injected := parsed.Rows[1].Cells[0]
	if injected.Inline.Text != "'=SUM(A1)" {
		t.Errorf("A2 = %q, want the escaped formula", injected.Inline.Text)
	}
	number := parsed.Rows[1].Cells[1]
	if number.Type != "" || number.Value != "4" {
		t.Errorf("B2 = %+v, want a numeric cell with 4", number)
	}
	escaped := parsed.Rows[3].Cells[2]
	if escaped.Inline.Text != "a<b>&c" {
		t.Errorf("C4 = %q, want the unescaped text back", escaped.Inline.Text)
	}
}

func TestGuardFormula(t *testing.T) {
	cases := map[string]string{
		"":        "",
		"plain":   "plain",
		"=1+1":    "'=1+1",
		"+1":      "'+1",
		"-1":      "'-1",
		"@cmd":    "'@cmd",
		"\tcmd":   "'\tcmd",
		"\rcmd":   "'\rcmd",
		" CVE-1 ": " CVE-1 ",
	}
	for input, want := range cases {
		if got := guardFormula(input); got != want {
			t.Errorf("guardFormula(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestExtension(t *testing.T) {
	for format, want := range map[string]string{
		FormatCSV: "csv", FormatXLSX: "xlsx", FormatJSON: "json", "xml": "",
	} {
		if got := Extension(format); got != want {
			t.Errorf("Extension(%q) = %q, want %q", format, got, want)
		}
	}
}
