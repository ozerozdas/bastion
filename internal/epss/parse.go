package epss

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ParseScores reads the gzipped EPSS feed and returns its scores keyed by CVE,
// together with the feed's score date.
//
// The feed is a gzip-compressed CSV with a leading comment line carrying the
// model version and score date, then a header (cve,epss,percentile) and one row
// per CVE. Percentile is a fraction between 0 and 1. Rows whose numbers do not
// parse are skipped: one damaged row must not discard the whole feed, which is
// what makes the daily refresh useful.
func ParseScores(r io.Reader) (map[string]Score, string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, "", fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	buffered := bufio.NewReader(gz)
	first, err := buffered.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, "", fmt.Errorf("read feed header: %w", err)
	}

	scoreDate := ""
	headerSeen := !strings.HasPrefix(first, "#")
	if !headerSeen {
		scoreDate = scoreDateFromComment(first)
	}

	reader := csv.NewReader(buffered)
	reader.FieldsPerRecord = 3
	if !headerSeen {
		if _, err := reader.Read(); err != nil && !errors.Is(err, io.EOF) {
			return nil, "", fmt.Errorf("read csv header: %w", err)
		}
	}

	scores := make(map[string]Score)
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("read csv row %d: %w", len(scores)+2, err)
		}
		cve := strings.TrimSpace(record[0])
		if cve == "" {
			continue
		}
		score, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			continue
		}
		percentile, err := strconv.ParseFloat(record[2], 64)
		if err != nil {
			continue
		}
		scores[cve] = Score{Score: score, Percentile: percentile}
	}
	if len(scores) == 0 {
		return nil, "", errors.New("feed contains no scores")
	}
	return scores, scoreDate, nil
}

// scoreDateFromComment extracts score_date from the feed's leading comment,
// for example "#model_version:v2026.06.15,score_date:2026-11-15T12:03:04Z".
func scoreDateFromComment(line string) string {
	for _, part := range strings.Split(strings.TrimSpace(line), ",") {
		if value, ok := strings.CutPrefix(part, "score_date:"); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
