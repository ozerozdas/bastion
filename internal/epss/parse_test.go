package epss

import (
	"bytes"
	"compress/gzip"
	"testing"
)

// gzipFeed compresses a feed document for the parser and HTTP tests.
func gzipFeed(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatalf("write gzip feed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip feed: %v", err)
	}
	return buf.Bytes()
}

const fixtureFeed = `#model_version:v2026.06.15,score_date:2026-11-15T12:03:04Z
cve,epss,percentile
CVE-2021-44228,0.99999,1.0
CVE-2022-0001,0.00042,0.1
CVE-BROKEN,not-a-number,0.5
`

func TestParseScores(t *testing.T) {
	scores, scoreDate, err := ParseScores(bytes.NewReader(gzipFeed(t, fixtureFeed)))
	if err != nil {
		t.Fatalf("ParseScores: %v", err)
	}
	if scoreDate != "2026-11-15T12:03:04Z" {
		t.Errorf("score date = %q, want the header's date", scoreDate)
	}
	if len(scores) != 2 {
		t.Fatalf("scores = %d, want 2 (the broken row is skipped)", len(scores))
	}
	log4j, ok := scores["CVE-2021-44228"]
	if !ok {
		t.Fatal("CVE-2021-44228 missing")
	}
	if log4j.Score != 0.99999 || log4j.Percentile != 1.0 {
		t.Errorf("log4j = %+v, want 0.99999 / 1.0", log4j)
	}
	if _, ok := scores["CVE-BROKEN"]; ok {
		t.Error("CVE-BROKEN should have been skipped")
	}
}

func TestParseScoresRejectsEmptyFeed(t *testing.T) {
	if _, _, err := ParseScores(bytes.NewReader(gzipFeed(t, "cve,epss,percentile\n"))); err == nil {
		t.Fatal("ParseScores accepted a feed with no scores")
	}
}
