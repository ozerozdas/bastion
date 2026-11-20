// Package epss implements bastion's opt-in EPSS exploit-prediction feed
// (PROJECT_SPEC.md §7.3).
//
// FIRST.org publishes a daily CSV of EPSS scores: the probability that a CVE is
// exploited in the next 30 days and the score's percentile. The download is
// opt-in and off by default; with the setting off no request is made. When it
// is on, the gzipped CSV is cached in the cache directory and refreshed at most
// once every 24 hours. Scores are read from the cache lazily, so a restart does
// not re-download and a scan never waits for the network.
//
// Every side effect sits behind a seam (HTTP client, clock, spawner), so tests
// never touch the network or wait on a goroutine.
package epss

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultURL is FIRST.org's "current" feed. It redirects to the dated file
	// of the day, which the default HTTP client follows.
	DefaultURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

	// refreshInterval is the minimum time between two downloads.
	refreshInterval = 24 * time.Hour
	// requestTimeout bounds one download. The feed is a few megabytes, so a
	// slow connection still finishes while a hung one cannot block forever.
	requestTimeout = 2 * time.Minute

	settingsFileName = "epss-settings.json"
	scoresFileName   = "epss_scores-current.csv.gz"
	metaFileName     = "epss-meta.json"
)

// Score is one CVE's EPSS prediction.
type Score struct {
	// Score is the probability of exploitation in the next 30 days (0..1).
	Score float64 `json:"score"`
	// Percentile is the score's rank among all scored CVEs (0..1).
	Percentile float64 `json:"percentile"`
}

// Status is the read-only view the API and the CLI render.
type Status struct {
	// Enabled is the stored opt-in setting.
	Enabled bool
	// LastRefresh is when the cached feed was last downloaded; zero when it
	// never was.
	LastRefresh time.Time
	// ScoreDate is the feed's own score_date, e.g. "2026-11-15T12:03:04Z".
	ScoreDate string
	// Count is the number of scored CVEs in the cached feed.
	Count int
	// Error explains the last failed download. The previous cache, if any,
	// stays in use.
	Error string
}

// Config configures a Service. Every zero value has a production default.
type Config struct {
	// DataDir holds the opt-in setting. It is the directory the release check
	// also stores its consent in.
	DataDir string
	// CacheDir holds the downloaded feed and its metadata. serve passes the
	// EPSS directory inside the cache directory.
	CacheDir string

	// URL overrides the feed location; tests point it at httptest.
	URL string
	// HTTPClient lets tests count requests. Its timeout is replaced.
	HTTPClient *http.Client
	// Now is the clock; tests use a fake to exercise expiry.
	Now func() time.Time
	// Spawn runs a background refresh. It defaults to `go f()`; tests run it
	// inline so an assertion after Status sees any request it started.
	Spawn func(func())
	// Version is the build version for the User-Agent header.
	Version string
	// Logger receives debug records for a failed refresh or unreadable cache.
	Logger *slog.Logger
}

// Service performs and caches the EPSS download. It is safe for concurrent use.
type Service struct {
	dataDir  string
	cacheDir string
	url      string
	client   *http.Client
	now      func() time.Time
	spawn    func(func())
	agent    string
	log      *slog.Logger

	// enabled mirrors the stored setting. Lookup reads it per finding, so it
	// must not touch the filesystem.
	enabled atomic.Bool

	// mu serialises refreshes, so a status call and a concurrent one cannot
	// both spend the daily budget.
	mu sync.Mutex
	// lastAttempt is when the last download was started. It counts towards the
	// 24-hour budget even when the cache write fails, so an unwritable cache
	// cannot turn into one request per call. Atomic because due() reads it
	// without mu.
	lastAttempt atomic.Int64
	// inFlight is the single-flight guard for background refreshes.
	inFlight atomic.Bool

	// loadMu serialises reading the cached feed into memory.
	loadMu sync.Mutex
	// loaded reports whether scores were read from the cache already.
	loaded atomic.Bool
	// scoresMu guards scores. Readers take the read lock only after loaded is
	// true, so the map is never swapped while it is read.
	scoresMu sync.RWMutex
	scores   map[string]Score
}

// New wires a Service with production defaults for the unset seams. It reads
// the stored setting and performs no network call.
func New(cfg Config) *Service {
	client := &http.Client{}
	if cfg.HTTPClient != nil {
		*client = *cfg.HTTPClient
	}
	client.Timeout = requestTimeout

	url := cfg.URL
	if url == "" {
		url = DefaultURL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	spawn := cfg.Spawn
	if spawn == nil {
		spawn = func(f func()) { go f() }
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	agent := "bastion"
	if cfg.Version != "" {
		agent = "bastion/" + cfg.Version
	}

	s := &Service{
		dataDir:  cfg.DataDir,
		cacheDir: cfg.CacheDir,
		url:      url,
		client:   client,
		now:      now,
		spawn:    spawn,
		agent:    agent,
		log:      logger,
	}
	s.enabled.Store(s.readSetting())
	return s
}

// Enabled reports the stored setting. It never touches the network.
func (s *Service) Enabled() bool {
	if s == nil {
		return false
	}
	return s.enabled.Load()
}

// SetEnabled stores the user's answer. Only the UI calls this; the CLI only
// reads. Turning the feed on clears the last attempt so a failed download can
// be retried at once instead of after a day.
func (s *Service) SetEnabled(enabled bool) error {
	if s.dataDir == "" {
		return errors.New("epss: data directory is required")
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("epss: create data directory: %w", err)
	}
	data, err := json.Marshal(settingsFile{Enabled: enabled})
	if err != nil {
		return fmt.Errorf("epss: encode settings: %w", err)
	}
	path := filepath.Join(s.dataDir, settingsFileName)
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("epss: store settings: %w", err)
	}
	s.enabled.Store(enabled)
	if enabled {
		s.lastAttempt.Store(0)
		if meta, ok := s.readMeta(); ok {
			meta.LastAttempt = time.Time{}
			meta.Error = ""
			if err := s.writeMeta(meta); err != nil {
				s.log.Debug("clear EPSS attempt", "error", err)
			}
		}
	}
	return nil
}

// Snapshot reports the stored setting and the cached feed without any network
// call.
func (s *Service) Snapshot() Status {
	status := Status{Enabled: s.enabled.Load()}
	if meta, ok := s.readMeta(); ok {
		status.LastRefresh = meta.LastRefresh
		status.ScoreDate = meta.ScoreDate
		status.Count = meta.Count
		status.Error = meta.Error
	}
	return status
}

// Status returns the cached view and starts one background refresh when the
// feed is enabled and the cache is older than 24 hours. It never waits for the
// network, so API handlers and `bastion serve` stay fast. Concurrent stale
// calls share the single in-flight refresh.
func (s *Service) Status() Status {
	status := s.Snapshot()
	if !status.Enabled || !s.due() {
		return status
	}
	if !s.inFlight.CompareAndSwap(false, true) {
		return status
	}
	// The request context belongs to the handler and is canceled when it
	// returns, so the background download gets its own bounded context.
	s.spawn(func() {
		defer s.inFlight.Store(false)
		_ = s.Refresh(context.Background())
	})
	return status
}

// Refresh downloads and parses the feed when it is enabled and due, and
// replaces the cache. A failure keeps the previous cache and is reported in
// Status.Error; it is never returned to a scan or a UI request.
func (s *Service) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.enabled.Load() || !s.due() {
		return nil
	}
	if s.cacheDir == "" {
		return errors.New("epss: cache directory is required")
	}

	attemptedAt := s.now().UTC()
	// Record the attempt before the request: if the download or the cache
	// write fails, the daily budget still holds.
	s.lastAttempt.Store(attemptedAt.UnixNano())
	meta, _ := s.readMeta()
	meta.LastAttempt = attemptedAt
	if err := s.writeMeta(meta); err != nil {
		s.log.Debug("store EPSS attempt", "error", err)
	}

	scores, scoreDate, err := s.download(ctx)
	if err != nil {
		meta.Error = err.Error()
		if writeErr := s.writeMeta(meta); writeErr != nil {
			s.log.Debug("store EPSS failure", "error", writeErr)
		}
		return fmt.Errorf("epss: refresh: %w", err)
	}

	meta.LastRefresh = attemptedAt
	meta.ScoreDate = scoreDate
	meta.Count = len(scores)
	meta.Error = ""
	if err := s.writeMeta(meta); err != nil {
		return fmt.Errorf("epss: store metadata: %w", err)
	}

	s.scoresMu.Lock()
	s.scores = scores
	s.scoresMu.Unlock()
	s.loaded.Store(true)
	return nil
}

// Lookup returns the score of one CVE. It is false when the feed is off, has
// not been downloaded yet or does not score the CVE, so callers never show a
// value that is not there.
func (s *Service) Lookup(cve string) (Score, bool) {
	if s == nil || cve == "" || !s.enabled.Load() {
		return Score{}, false
	}
	if !s.loaded.Load() {
		s.load()
	}
	s.scoresMu.RLock()
	defer s.scoresMu.RUnlock()
	score, ok := s.scores[cve]
	return score, ok
}

// load reads the cached feed into memory once. A missing or damaged cache is
// not an error the caller can act on: the next refresh replaces it, and until
// then findings simply carry no EPSS value.
func (s *Service) load() {
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if s.loaded.Load() {
		return
	}
	file, err := os.Open(filepath.Join(s.cacheDir, scoresFileName))
	if err != nil {
		return
	}
	scores, _, err := ParseScores(file)
	closeErr := file.Close()
	if err != nil {
		s.log.Debug("read cached EPSS feed", "error", err)
		return
	}
	if closeErr != nil {
		s.log.Debug("close cached EPSS feed", "error", closeErr)
	}
	s.scoresMu.Lock()
	s.scores = scores
	s.scoresMu.Unlock()
	s.loaded.Store(true)
}

// download fetches the feed, verifies it parses, and only then replaces the
// cached file, so a truncated download never becomes the cache.
func (s *Service) download(ctx context.Context) (map[string]Score, string, error) {
	if err := os.MkdirAll(s.cacheDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("create cache directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build feed request: %w", err)
	}
	req.Header.Set("User-Agent", s.agent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("feed answered %d, expected 200", resp.StatusCode)
	}

	temp, err := os.CreateTemp(s.cacheDir, "epss-*.csv.gz")
	if err != nil {
		return nil, "", fmt.Errorf("create cache file: %w", err)
	}
	tempPath := temp.Name()
	// The rename below consumes the file; a failure leaves it behind.
	defer func() { _ = os.Remove(tempPath) }()

	if _, err := io.Copy(temp, resp.Body); err != nil {
		_ = temp.Close()
		return nil, "", fmt.Errorf("download feed: %w", err)
	}
	if err := temp.Close(); err != nil {
		return nil, "", fmt.Errorf("close cache file: %w", err)
	}

	file, err := os.Open(tempPath) //nolint:gosec // G304: tempPath comes from os.CreateTemp in the cache directory.
	if err != nil {
		return nil, "", fmt.Errorf("open downloaded feed: %w", err)
	}
	scores, scoreDate, err := ParseScores(file)
	closeErr := file.Close()
	if err != nil {
		return nil, "", fmt.Errorf("parse feed: %w", err)
	}
	if closeErr != nil {
		return nil, "", fmt.Errorf("close downloaded feed: %w", closeErr)
	}
	if err := os.Rename(tempPath, filepath.Join(s.cacheDir, scoresFileName)); err != nil {
		return nil, "", fmt.Errorf("store feed: %w", err)
	}
	return scores, scoreDate, nil
}

// due reports whether the daily budget allows another download.
func (s *Service) due() bool {
	var last time.Time
	if meta, ok := s.readMeta(); ok {
		last = meta.LastAttempt
	}
	if nanos := s.lastAttempt.Load(); nanos != 0 {
		if attempt := time.Unix(0, nanos); attempt.After(last) {
			last = attempt
		}
	}
	if last.IsZero() {
		return true
	}
	return s.now().Sub(last) >= refreshInterval
}

// settingsFile is the on-disk opt-in document. A missing or unreadable file
// means off: the setting fails closed, so a damaged file never enables a
// request.
type settingsFile struct {
	Enabled bool `json:"enabled"`
}

// metaFile is the cache's metadata. LastAttempt is set on every attempt,
// successful or not, and keeps the daily budget across restarts.
type metaFile struct {
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastRefresh time.Time `json:"last_refresh,omitempty"`
	ScoreDate   string    `json:"score_date,omitempty"`
	Count       int       `json:"count,omitempty"`
	Error       string    `json:"error,omitempty"`
}

func (s *Service) readSetting() bool {
	if s.dataDir == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join(s.dataDir, settingsFileName))
	if err != nil {
		return false
	}
	var stored settingsFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return false
	}
	return stored.Enabled
}

func (s *Service) readMeta() (metaFile, bool) {
	data, err := os.ReadFile(filepath.Join(s.cacheDir, metaFileName))
	if err != nil {
		return metaFile{}, false
	}
	var meta metaFile
	if err := json.Unmarshal(data, &meta); err != nil {
		return metaFile{}, false
	}
	return meta, true
}

func (s *Service) writeMeta(meta metaFile) error {
	if s.cacheDir == "" {
		return errors.New("epss: cache directory is required")
	}
	if err := os.MkdirAll(s.cacheDir, 0o700); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	return writeFileAtomic(filepath.Join(s.cacheDir, metaFileName), append(data, '\n'))
}

// writeFileAtomic writes data through a temporary file in the same directory
// and renames it into place, so a reader never sees half a document.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
