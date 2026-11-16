// Package export writes findings tables as CSV, XLSX or JSON.
//
// It is pure: the callers build a Table from the reports read model and this
// package only encodes it. CSV is RFC 4180 with a UTF-8 BOM so Excel opens it
// as UTF-8; XLSX is a minimal single-sheet workbook written with archive/zip and
// encoding/xml, so bastion needs no spreadsheet dependency. Text cells that a
// spreadsheet could evaluate as a formula are prefixed with an apostrophe in
// CSV and XLSX (formula injection).
package export

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"
	"time"
)

// Column is one output column: a stable JSON key and the header text CSV and
// XLSX show.
type Column struct {
	Key    string
	Header string
}

// Cell is one table cell. A nil Number is text; a Number is written as a
// numeric cell (XLSX) and a bare number (CSV, JSON).
type Cell struct {
	Text   string
	Number *float64
}

// TextCell is a text cell.
func TextCell(text string) Cell { return Cell{Text: text} }

// NumberCell is a numeric cell.
func NumberCell(value float64) Cell {
	return Cell{Number: &value}
}

// IntCell is a whole-number cell.
func IntCell(value int64) Cell { return NumberCell(float64(value)) }

// Table is an ordered set of columns and rows. Every row has one cell per
// column.
type Table struct {
	Columns []Column
	Rows    [][]Cell
}

// Formats the export endpoint accepts.
const (
	FormatCSV  = "csv"
	FormatXLSX = "xlsx"
	FormatJSON = "json"
)

// ValidFormat reports whether format is one the endpoint can write.
func ValidFormat(format string) bool {
	switch format {
	case FormatCSV, FormatXLSX, FormatJSON:
		return true
	}
	return false
}

// Extension is the filename extension of a format.
func Extension(format string) string {
	switch format {
	case FormatCSV:
		return "csv"
	case FormatXLSX:
		return "xlsx"
	case FormatJSON:
		return "json"
	}
	return ""
}

// CSV writes the table as RFC 4180 CSV with a UTF-8 BOM and CRLF line endings.
func CSV(table Table) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\uFEFF")

	writer := csv.NewWriter(&buf)
	writer.UseCRLF = true

	header := make([]string, len(table.Columns))
	for i, column := range table.Columns {
		header[i] = column.Header
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("export: write CSV header: %w", err)
	}

	for _, row := range table.Rows {
		record := make([]string, len(row))
		for i, cell := range row {
			record[i] = csvValue(cell)
		}
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("export: write CSV row: %w", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("export: write CSV: %w", err)
	}
	return buf.Bytes(), nil
}

// JSON writes the table as an array of objects keyed by Column.Key. Keys keep
// their column order, and numeric cells stay JSON numbers.
func JSON(table Table) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for rowIndex, row := range table.Rows {
		if rowIndex > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('{')
		for columnIndex, column := range table.Columns {
			if columnIndex > 0 {
				buf.WriteByte(',')
			}
			key, err := json.Marshal(column.Key)
			if err != nil {
				return nil, fmt.Errorf("export: encode JSON key %q: %w", column.Key, err)
			}
			buf.Write(key)
			buf.WriteByte(':')
			if columnIndex >= len(row) {
				buf.WriteString("null")
				continue
			}
			value, err := json.Marshal(jsonValue(row[columnIndex]))
			if err != nil {
				return nil, fmt.Errorf("export: encode JSON cell %q: %w", column.Key, err)
			}
			buf.Write(value)
		}
		buf.WriteByte('}')
	}
	buf.WriteString("]\n")
	return buf.Bytes(), nil
}

// jsonValue is a text cell's string or a numeric cell's float.
func jsonValue(cell Cell) any {
	if cell.Number != nil {
		return *cell.Number
	}
	return cell.Text
}

// csvValue is a cell's CSV text: numeric cells keep their bare number, text
// cells are guarded against formula injection.
func csvValue(cell Cell) string {
	if cell.Number != nil {
		return formatNumber(*cell.Number)
	}
	return guardFormula(cell.Text)
}

// formatNumber renders a float without a trailing ".0" on whole numbers.
func formatNumber(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// guardFormula prefixes text a spreadsheet would evaluate as a formula, so an
// exported finding can never run. It mirrors the OWASP guidance for CSV
// injection: =, +, -, @, tab and carriage return at the start of a cell.
func guardFormula(text string) string {
	if text == "" {
		return text
	}
	switch text[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + text
	}
	return text
}

// xlsxEpoch is the modification time every zip entry carries. A fixed time
// makes the workbook reproducible; a zero time is not a valid DOS date.
var xlsxEpoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// XLSX writes the table as one-sheet XLSX. Text is inline (no shared strings),
// numbers are numeric cells, and the header row is bold.
func XLSX(table Table) ([]byte, error) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)

	entries := []struct {
		name string
		body []byte
	}{
		{"[Content_Types].xml", []byte(contentTypesXML)},
		{"_rels/.rels", []byte(rootRelsXML)},
		{"xl/workbook.xml", []byte(workbookXML)},
		{"xl/_rels/workbook.xml.rels", []byte(workbookRelsXML)},
		{"xl/styles.xml", []byte(stylesXML)},
		{"xl/worksheets/sheet1.xml", sheetXML(table)},
	}
	for _, entry := range entries {
		header := &zip.FileHeader{
			Name:     entry.name,
			Method:   zip.Deflate,
			Modified: xlsxEpoch,
		}
		file, err := writer.CreateHeader(header)
		if err != nil {
			return nil, fmt.Errorf("export: create %s: %w", entry.name, err)
		}
		if _, err := file.Write(entry.body); err != nil {
			return nil, fmt.Errorf("export: write %s: %w", entry.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("export: close XLSX archive: %w", err)
	}
	return archive.Bytes(), nil
}

// sheetXML builds xl/worksheets/sheet1.xml.
func sheetXML(table Table) []byte {
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	buf.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)

	header := make([]Cell, len(table.Columns))
	for i, column := range table.Columns {
		header[i] = TextCell(column.Header)
	}
	writeRow(&buf, 1, header, true)
	for i, row := range table.Rows {
		writeRow(&buf, i+2, row, false)
	}

	buf.WriteString(`</sheetData></worksheet>`)
	return buf.Bytes()
}

// writeRow writes one <row>. Header cells use the bold style.
func writeRow(buf *bytes.Buffer, row int, cells []Cell, header bool) {
	fmt.Fprintf(buf, `<row r="%d">`, row)
	style := 0
	if header {
		style = 1
	}
	for column, cell := range cells {
		ref := columnName(column) + strconv.Itoa(row)
		if cell.Number != nil {
			fmt.Fprintf(buf, `<c r="%s" s="%d"><v>%s</v></c>`,
				ref, style, formatNumber(*cell.Number))
			continue
		}
		fmt.Fprintf(buf, `<c r="%s" t="inlineStr" s="%d"><is><t xml:space="preserve">%s</t></is></c>`,
			ref, style, escapeXML(guardFormula(cell.Text)))
	}
	buf.WriteString(`</row>`)
}

// columnName maps a zero-based column index to its A1 letters (0 -> A,
// 26 -> AA).
func columnName(index int) string {
	name := make([]byte, 0, 2)
	for index >= 0 {
		name = append([]byte{byte('A' + index%26)}, name...)
		index = index/26 - 1
	}
	return string(name)
}

// escapeXML escapes text for an XML text node.
func escapeXML(text string) string {
	var buf bytes.Buffer
	// EscapeText only fails on a write error, which a bytes.Buffer cannot have.
	_ = xml.EscapeText(&buf, []byte(text))
	return buf.String()
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`

const workbookXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Findings" sheetId="1" r:id="rId1"/></sheets></workbook>`

const workbookRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`

const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`
