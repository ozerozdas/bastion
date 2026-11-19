// Package securitynews implements the opt-in Security News feed (#192).
//
// The feature aggregates a fixed set of well-known security RSS/Atom feeds on
// the server, so the UI and the MCP server read one cache instead of hitting
// third-party sites from the browser. It is off by default: while the setting
// is off, no request is made.
//
// Feed content is untrusted external input. Only the title, source, publication
// date, an http(s) link and a short plain-text summary are kept; HTML is
// stripped before anything reaches the API or an agent.
package securitynews

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTTL is how long one source's items are served from memory before
	// a refresh is attempted.
	DefaultTTL = 30 * time.Minute
	// errorTTL is the shorter retry window after a failed fetch, so a
	// transient outage recovers in minutes instead of half an hour.
	errorTTL = 2 * time.Minute
	// requestTimeout bounds one feed download. Feeds are small; a slow source
	// must not hold up the panel or another source.
	requestTimeout = 8 * time.Second
	// maxFeedBytes caps one response body. A feed is far smaller; the cap keeps
	// a hostile or broken endpoint from filling memory.
	maxFeedBytes = 2 << 20
	// MaxSummaryRunes is the longest summary kept, in characters.
	MaxSummaryRunes = 280
	// MaxTitleRunes is the longest title kept, in characters.
	MaxTitleRunes = 300
	// MaxItems caps how many items one feed response carries.
	MaxItems = 100

	settingsFileName = "security-news-settings.json"
)

// ErrUnknownSource marks a Set call naming a source id that is not preset.
var ErrUnknownSource = errors.New("securitynews: unknown source")

// Source is one preset feed. The list is fixed: custom RSS is out of scope.
type Source struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"-"`
	Recommended bool   `json:"recommended"`
}

// Sources is the preset source list shown in Configuration. The URLs come from
// issue #192; each fetch is isolated, so one dead feed never hides the others.
var Sources = []Source{
	{ID: "the-hacker-news", Name: "The Hacker News", URL: "https://feeds.feedburner.com/TheHackersNews", Recommended: true},
	{ID: "bleepingcomputer", Name: "BleepingComputer", URL: "https://www.bleepingcomputer.com/feed/", Recommended: true},
	{ID: "cisa-advisories", Name: "CISA Advisories", URL: "https://www.cisa.gov/cybersecurity-advisories/all.xml", Recommended: true},
	{ID: "sans-isc", Name: "SANS ISC", URL: "https://isc.sans.edu/rssfeed.xml", Recommended: true},
	{ID: "krebs-on-security", Name: "Krebs on Security", URL: "https://krebsonsecurity.com/feed/"},
	{ID: "securityweek", Name: "SecurityWeek", URL: "https://www.securityweek.com/feed/"},
	{ID: "dark-reading", Name: "Dark Reading", URL: "https://www.darkreading.com/rss.xml"},
	{ID: "exploit-db", Name: "Exploit-DB", URL: "https://www.exploit-db.com/rss.xml"},
	{ID: "project-zero", Name: "Google Project Zero", URL: "https://googleprojectzero.blogspot.com/feeds/posts/default"},
	{ID: "portswigger-research", Name: "PortSwigger Research", URL: "https://portswigger.net/research/rss"},
	{ID: "reddit-netsec", Name: "r/netsec", URL: "https://www.reddit.com/r/netsec/.rss"},
}

// Item is one news entry. The fields are the only ones a feed can expose.
type Item struct {
	Title     string    `json:"title"`
	Source    string    `json:"source"`
	SourceID  string    `json:"source_id"`
	Published time.Time `json:"published"`
	Link      string    `json:"link"`
	Summary   string    `json:"summary"`
}

// SourceState is one source's setting and last fetch result.
type SourceState struct {
	Source
	Enabled bool
	// Error is the last failed fetch's message; the previous items, if any,
	// are still served.
	Error string
}

// Feed is the read model the API and the dashboard render.
type Feed struct {
	Enabled bool
	Sources []SourceState
	Items   []Item
}

// Config configures a Service. Every zero value has a production default.
type Config struct {
	// DataDir stores the opt-in setting. It is the directory the other opt-in
	// modules also keep their settings in.
	DataDir string

	// Sources overrides the preset list; tests point it at httptest servers so
	// no test can reach a real feed.
	Sources []Source
	// TTL overrides the in-memory cache lifetime; tests use a short one.
	TTL time.Duration
	// Timeout overrides one request's deadline.
	Timeout time.Duration
	// HTTPClient lets tests reuse a client; its timeout is replaced.
	HTTPClient *http.Client
	// Now is the clock; tests use a fake.
	Now func() time.Time
	// Version is the build version for the User-Agent header.
	Version string
	// Logger receives debug records for a failed fetch.
	Logger *slog.Logger
}

// Service fetches, caches and reads the security news feeds. It is safe for
// concurrent use.
type Service struct {
	dataDir string
	sources []Source
	urls    map[string]string
	ttl     time.Duration
	timeout time.Duration
	client  *http.Client
	now     func() time.Time
	agent   string
	log     *slog.Logger

	// mu guards the settings only. It is never held across a network call, so
	// Enabled and Set stay fast while a feed refresh is in flight.
	mu           sync.Mutex
	enabled      bool
	selected     map[string]bool
	generation   uint64
	settingsMod  time.Time
	settingsSeen bool

	// refreshMu single-flights a feed refresh, so concurrent callers share one
	// round of requests without blocking the settings.
	refreshMu sync.Mutex

	// cacheMu guards cache, which is also read and written without refreshMu.
	cacheMu sync.Mutex
	cache   map[string]cacheEntry
}

// cacheEntry is one source's in-memory cache.
type cacheEntry struct {
	items   []Item
	fetched time.Time
	err     string
}

// New wires a Service. It reads the stored setting and performs no network
// call.
func New(cfg Config) *Service {
	client := &http.Client{}
	if cfg.HTTPClient != nil {
		*client = *cfg.HTTPClient
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = requestTimeout
	}
	client.Timeout = timeout
	// A feed may redirect, but only within its own host and over http(s):
	// otherwise a feed could bounce the server to an internal or non-HTTP
	// target. Five hops is more than any real feed needs.
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
			return fmt.Errorf("redirect to unsupported scheme %q", request.URL.Scheme)
		}
		if len(via) > 0 && !strings.EqualFold(request.URL.Host, via[0].URL.Host) {
			return fmt.Errorf("redirect to another host %q", request.URL.Host)
		}
		return nil
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	agent := "bastion"
	if cfg.Version != "" {
		agent = "bastion/" + cfg.Version
	}

	sources := cfg.Sources
	if sources == nil {
		sources = Sources
	}
	urls := make(map[string]string, len(sources))
	for _, source := range sources {
		urls[source.ID] = source.URL
	}

	s := &Service{
		dataDir: cfg.DataDir,
		sources: sources,
		urls:    urls,
		ttl:     ttl,
		timeout: timeout,
		client:  client,
		now:     now,
		agent:   agent,
		log:     logger,
		cache:   make(map[string]cacheEntry, len(sources)),
	}
	s.enabled, s.selected = s.readSettings()
	s.settingsMod = s.settingsStamp()
	s.settingsSeen = true
	return s
}

// Enabled reports the stored setting. It never touches the network. A changed
// settings file is picked up first, so a long-lived `bastion mcp` process sees
// the UI's toggle.
func (s *Service) Enabled() bool {
	if s == nil {
		return false
	}
	s.reloadIfChanged()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled
}

// Set stores the feature switch and the source selection. A nil sources slice
// means "keep the current selection", so turning the feature on from a client
// that does not send a list starts from the recommended set. An unknown source
// id is rejected and nothing is written.
func (s *Service) Set(enabled bool, sources []string) error {
	if s.dataDir == "" {
		return errors.New("securitynews: data directory is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.selected
	if sources != nil {
		next = make(map[string]bool, len(sources))
		for _, id := range sources {
			if !s.known(id) {
				return fmt.Errorf("%w %q", ErrUnknownSource, id)
			}
			next[id] = true
		}
	}
	if next == nil {
		next = recommendedFor(s.sources)
	}

	stored := settingsFile{Enabled: enabled}
	// Keep the stored list stable and explicit, so a disabled source stays
	// disabled across restarts even when the recommended set changes.
	for _, source := range s.sources {
		if next[source.ID] {
			stored.Sources = append(stored.Sources, source.ID)
		}
	}
	if stored.Sources == nil {
		stored.Sources = []string{}
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("securitynews: encode settings: %w", err)
	}
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		return fmt.Errorf("securitynews: create data directory: %w", err)
	}
	path := filepath.Join(s.dataDir, settingsFileName)
	if err := writeFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("securitynews: store settings: %w", err)
	}

	s.enabled = enabled
	s.selected = next
	s.generation++
	// Our own write is the newest stamp; a later reload compares against it.
	s.settingsMod = s.settingsStamp()
	if !enabled {
		// Disabling frees the cached third-party content and guarantees the
		// next enable starts from a fresh fetch, not stale items. An in-flight
		// Feed notices the generation change and will not repopulate it.
		s.cacheMu.Lock()
		s.cache = make(map[string]cacheEntry, len(s.sources))
		s.cacheMu.Unlock()
	}
	return nil
}

// Settings returns the stored switch and source states without a fetch. The
// API's PUT response uses it so storing a choice never reaches the network.
func (s *Service) Settings() Feed {
	if s == nil {
		return Feed{}
	}
	s.reloadIfChanged()
	s.mu.Lock()
	defer s.mu.Unlock()
	return Feed{Enabled: s.enabled, Sources: s.sourceStates()}
}

// Feed returns the source states and the items of every enabled source. When
// the feature is off it returns the settings and no items, without a network
// call. Stale sources refresh concurrently, so one slow feed does not delay
// the others. The settings lock is not held across those requests.
func (s *Service) Feed(ctx context.Context) Feed {
	if s == nil {
		return Feed{}
	}

	s.reloadIfChanged()
	feed, enabled, _, _ := s.feedSnapshot()
	if !enabled {
		return feed
	}

	// One refresh at a time; a second caller waits and then sees the cache.
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	// The setting may have changed while waiting for the refresh slot.
	feed, enabled, selected, gen := s.feedSnapshot()
	if !enabled {
		return feed
	}

	type result struct {
		items   []Item
		fetched bool
		err     string
	}
	results := make([]result, len(s.sources))
	var fetchIndexes []int

	s.cacheMu.Lock()
	now := s.now()
	for index, source := range s.sources {
		if !selected[source.ID] {
			continue
		}
		entry, ok := s.cache[source.ID]
		ttl := s.ttl
		if entry.err != "" {
			ttl = errorTTL
		}
		if ok && now.Sub(entry.fetched) < ttl {
			results[index] = result{items: entry.items, err: entry.err}
			continue
		}
		fetchIndexes = append(fetchIndexes, index)
	}
	s.cacheMu.Unlock()

	// Detach from the caller's cancellation: a browser reload must not leave
	// a half-refreshed cache behind. Each source still has its own deadline.
	fetchCtx := context.WithoutCancel(ctx)
	var wg sync.WaitGroup
	for _, index := range fetchIndexes {
		wg.Add(1)
		go func(index int, source Source) {
			defer wg.Done()
			items, err := s.fetch(fetchCtx, source)
			results[index] = result{items: items, fetched: true, err: err}
		}(index, s.sources[index])
	}
	wg.Wait()

	// A disable during the fetch clears the cache and bumps the generation;
	// the late results must not bring the content back.
	if !s.stillCurrent(gen) {
		return s.settingsFeed()
	}

	s.cacheMu.Lock()
	for _, index := range fetchIndexes {
		source := s.sources[index]
		result := results[index]
		entry := cacheEntry{items: result.items, fetched: now, err: result.err}
		if result.err != "" {
			// Keep the previous items on a failed refresh: a transient outage
			// should not empty the dashboard. The current response serves them
			// too, alongside the source's error.
			previous := s.cache[source.ID].items
			entry.items = previous
			results[index].items = previous
		}
		s.cache[source.ID] = entry
	}
	s.cacheMu.Unlock()

	var items []Item
	for index, source := range s.sources {
		if !selected[source.ID] {
			continue
		}
		feed.Sources[index].Error = results[index].err
		items = append(items, results[index].items...)
	}
	feed.Items = mergeItems(items)
	return feed
}

// feedSnapshot copies the settings Feed needs, so the rest of the call can run
// without the settings lock.
func (s *Service) feedSnapshot() (Feed, bool, map[string]bool, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	selected := make(map[string]bool, len(s.selected))
	for id := range s.selected {
		selected[id] = true
	}
	feed := Feed{Enabled: s.enabled, Sources: s.sourceStates()}
	return feed, s.enabled, selected, s.generation
}

// settingsFeed reads the current settings without fetching, used when a
// refresh is superseded.
func (s *Service) settingsFeed() Feed {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Feed{Enabled: s.enabled, Sources: s.sourceStates()}
}

// stillCurrent reports whether the refresh generation that started a fetch is
// still the active one.
func (s *Service) stillCurrent(gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled && s.generation == gen
}

// reloadIfChanged re-reads the settings file when its modification time moved,
// so a separate process (the MCP server) follows the UI without a restart.
func (s *Service) reloadIfChanged() {
	if s == nil || s.dataDir == "" {
		return
	}
	stamp := s.settingsStamp()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settingsSeen && s.settingsMod.Equal(stamp) {
		return
	}
	enabled, selected := s.readSettings()
	s.enabled = enabled
	s.selected = selected
	s.settingsMod = stamp
	s.settingsSeen = true
	s.generation++
	if !enabled {
		s.cacheMu.Lock()
		s.cache = make(map[string]cacheEntry, len(s.sources))
		s.cacheMu.Unlock()
	}
}

// settingsStamp is the settings file's modification time, or the zero time
// when the file does not exist.
func (s *Service) settingsStamp() time.Time {
	if s.dataDir == "" {
		return time.Time{}
	}
	info, err := os.Stat(filepath.Join(s.dataDir, settingsFileName))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// sourceStates maps the settings onto the preset list, in the list's order.
// Callers hold mu.
func (s *Service) sourceStates() []SourceState {
	states := make([]SourceState, len(s.sources))
	for index, source := range s.sources {
		states[index] = SourceState{Source: source, Enabled: s.selected[source.ID]}
	}
	return states
}

// known reports whether id is one of the preset sources.
func (s *Service) known(id string) bool {
	_, ok := s.urls[id]
	return ok
}

// settingsFile is the on-disk document. A missing or unreadable file means
// off, so a damaged file never enables network requests.
type settingsFile struct {
	Enabled bool     `json:"enabled"`
	Sources []string `json:"sources"`
}

// readSettings returns the stored switch and selection. A fresh install has
// the feature off and the recommended sources selected, ready for the moment
// the user enables it. Callers hold no lock.
func (s *Service) readSettings() (bool, map[string]bool) {
	selected := recommendedFor(s.sources)
	if s.dataDir == "" {
		return false, selected
	}
	data, err := os.ReadFile(filepath.Join(s.dataDir, settingsFileName))
	if err != nil {
		return false, selected
	}
	var stored settingsFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return false, selected
	}
	// An explicitly stored list wins, including an empty one: disabling every
	// source is a real choice.
	selected = make(map[string]bool, len(stored.Sources))
	for _, id := range stored.Sources {
		if s.known(id) {
			selected[id] = true
		}
	}
	return stored.Enabled, selected
}

// recommendedFor is recommended() over an arbitrary list, so the test service
// uses its own sources' flags.
func recommendedFor(sources []Source) map[string]bool {
	selected := make(map[string]bool)
	for _, source := range sources {
		if source.Recommended {
			selected[source.ID] = true
		}
	}
	return selected
}

// mergeItems dedupes by link, sorts newest first and caps the result.
func mergeItems(items []Item) []Item {
	seen := make(map[string]struct{}, len(items))
	merged := make([]Item, 0, len(items))
	for _, item := range items {
		if item.Link == "" {
			continue
		}
		if _, ok := seen[item.Link]; ok {
			continue
		}
		seen[item.Link] = struct{}{}
		merged = append(merged, item)
	}
	sort.SliceStable(merged, func(a, b int) bool {
		first, second := merged[a].Published, merged[b].Published
		if first.IsZero() != second.IsZero() {
			return !first.IsZero()
		}
		if !first.Equal(second) {
			return first.After(second)
		}
		return strings.ToLower(merged[a].Title) < strings.ToLower(merged[b].Title)
	})
	if len(merged) > MaxItems {
		merged = merged[:MaxItems]
	}
	return merged
}

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
