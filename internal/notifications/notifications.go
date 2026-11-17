// Package notifications tells an external service (Slack, #44/#45) about
// findings a scan introduced.
//
// A scan that succeeds is diffed against the asset's previous succeeded scan
// with reports.ScanDiff. When the diff adds at least one finding at or above
// the stored threshold, every enabled notifier is called once with a summary.
// The very first scan of an asset is deliberately skipped: with no baseline
// every finding would look new, and a fresh install would send a flood.
//
// Notification failures are logged and never reach the scan: the manager calls
// ScanSucceeded on its own goroutine, and this package bounds the whole attempt
// with a timeout.
package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store/sqlcdb"
)

// Thresholds a notification can use. High means critical and high findings;
// critical means critical findings only.
const (
	ThresholdHigh     = "high"
	ThresholdCritical = "critical"
)

const (
	// settingsFileName holds the non-secret notification choices in the data
	// directory, next to the EPSS and reachability settings (#44).
	settingsFileName = "notifications-settings.json"

	// DefaultTimeout bounds one notification attempt: the diff and every
	// notifier call share it, so a hanging webhook cannot keep a goroutine
	// (or the process at shutdown) around forever.
	DefaultTimeout = 15 * time.Second

	// MaxWebhookLength is the longest accepted Slack webhook URL. A real one
	// is ~90 characters; the limit rejects garbage before it reaches the
	// keyring.
	MaxWebhookLength = 512
)

var (
	// ErrUnavailable means the service was not built with what it needs.
	ErrUnavailable = errors.New("notifications: unavailable")
	// ErrInvalid marks a setting the service refuses; handlers map it to 400.
	ErrInvalid = errors.New("notifications: invalid")
	// ErrNoWebhook means no Slack webhook is stored, so a test message has
	// nowhere to go.
	ErrNoWebhook = errors.New("no Slack webhook is configured")
)

// Settings are the stored, non-secret notification choices. The Slack webhook
// itself lives in the OS keyring and is never part of this struct.
type Settings struct {
	// Enabled is the master switch. With it off no notifier is called.
	Enabled bool `json:"enabled"`
	// Threshold is ThresholdHigh or ThresholdCritical.
	Threshold string `json:"threshold"`
	// SlackEnabled turns the Slack notifier on independently of the master
	// switch.
	SlackEnabled bool `json:"slack_enabled"`
}

// DefaultSettings is the state of a fresh install: notifications off, high
// threshold, Slack off.
func DefaultSettings() Settings {
	return Settings{Threshold: ThresholdHigh}
}

// Summary is what a notifier receives for one qualifying scan.
type Summary struct {
	AssetID   int64
	AssetName string
	ScanID    int64
	// Counts are the new findings of the scan, per severity.
	Counts Counts
	// URL links to the asset's findings list.
	URL string
	// Test marks the settings modal's "send test" message.
	Test bool
}

// Counts is a finding count per severity.
type Counts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// Notifier delivers one Summary to an external service. Name is stable and
// used in logs and the enabled check. Notify is called on a goroutine owned by
// this package, never on a scan worker.
type Notifier interface {
	Name() string
	Notify(ctx context.Context, summary Summary) error
}

// UpdateInput is the settable part of the settings. A nil field is left
// untouched; SlackWebhook and ClearSlackWebhook are mutually exclusive.
type UpdateInput struct {
	Enabled           *bool
	Threshold         *string
	SlackEnabled      *bool
	SlackWebhook      *string
	ClearSlackWebhook bool
}

// Config wires a Service.
type Config struct {
	// DataDir is where the non-secret settings file lives.
	DataDir string
	// DB backs the previous-scan diff and the asset name lookup.
	DB *sql.DB
	// Secrets holds the Slack webhook in the OS keyring.
	Secrets secrets.Store
	// Reports performs the scan diff.
	Reports *reports.Service
	// BaseURL is the serve listen address, used to build report links.
	BaseURL string
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// HTTPClient is used by the Slack notifier. Nil means a 10s client.
	HTTPClient *http.Client
	// Notifiers replaces the default Slack notifier. Tests use a fake.
	Notifiers []Notifier
	// Timeout bounds one attempt; zero means DefaultTimeout.
	Timeout time.Duration
}

// Service stores the notification settings and dispatches a succeeded scan to
// the enabled notifiers. It is safe for concurrent use.
type Service struct {
	mu       sync.Mutex
	settings Settings

	path    string
	db      *sql.DB
	secrets secrets.Store
	reports *reports.Service
	baseURL string
	log     *slog.Logger
	timeout time.Duration

	notifiers []Notifier
	slack     *Slack
}

// New validates cfg and loads the stored settings. A missing or unreadable
// settings file means DefaultSettings, exactly like the other opt-in modules.
func New(cfg Config) (*Service, error) {
	if cfg.DataDir == "" {
		return nil, errors.New("notifications: data directory is required")
	}
	if cfg.DB == nil {
		return nil, errors.New("notifications: database is required")
	}
	if cfg.Reports == nil {
		return nil, errors.New("notifications: reports service is required")
	}
	if cfg.Secrets == nil {
		return nil, errors.New("notifications: secret store is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	service := &Service{
		settings: DefaultSettings(),
		path:     filepath.Join(cfg.DataDir, settingsFileName),
		db:       cfg.DB,
		secrets:  cfg.Secrets,
		reports:  cfg.Reports,
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		log:      logger,
		timeout:  timeout,
	}
	service.settings = service.readSettings()

	notifiers := cfg.Notifiers
	if notifiers == nil {
		service.slack = NewSlack(cfg.Secrets, cfg.HTTPClient)
		notifiers = []Notifier{service.slack}
	} else {
		for _, notifier := range notifiers {
			if slack, ok := notifier.(*Slack); ok {
				service.slack = slack
			}
		}
	}
	service.notifiers = notifiers
	return service, nil
}

// Settings returns a copy of the stored choices.
func (s *Service) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

// SlackConfigured reports whether a Slack webhook is stored. The value itself
// never leaves the keyring.
func (s *Service) SlackConfigured() bool {
	webhook, err := s.secrets.Get(SlackWebhookKey)
	return err == nil && webhook != ""
}

// Update validates in, applies the settable fields and stores them. The Slack
// webhook is written to the keyring, never to the settings file.
func (s *Service) Update(in UpdateInput) (Settings, error) {
	if in.SlackWebhook != nil && in.ClearSlackWebhook {
		return Settings{}, fmt.Errorf("%w: set or clear the Slack webhook, not both", ErrInvalid)
	}

	webhook := ""
	if in.SlackWebhook != nil {
		trimmed := strings.TrimSpace(*in.SlackWebhook)
		if err := ValidateSlackWebhook(trimmed); err != nil {
			return Settings{}, err
		}
		webhook = trimmed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.settings
	if in.Enabled != nil {
		next.Enabled = *in.Enabled
	}
	if in.SlackEnabled != nil {
		next.SlackEnabled = *in.SlackEnabled
	}
	if in.Threshold != nil {
		threshold := strings.TrimSpace(*in.Threshold)
		if !ValidThreshold(threshold) {
			return Settings{}, fmt.Errorf("%w: threshold must be %q or %q",
				ErrInvalid, ThresholdHigh, ThresholdCritical)
		}
		next.Threshold = threshold
	}

	// Apply the keyring change first: if it fails, the stored settings stay
	// exactly as they were.
	if webhook != "" {
		if err := s.secrets.Set(SlackWebhookKey, webhook); err != nil {
			return Settings{}, fmt.Errorf("notifications: store Slack webhook: %w", err)
		}
	}
	if in.ClearSlackWebhook {
		if err := s.secrets.Delete(SlackWebhookKey); err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return Settings{}, fmt.Errorf("notifications: clear Slack webhook: %w", err)
		}
	}

	if err := s.writeSettings(next); err != nil {
		return Settings{}, err
	}
	s.settings = next
	return next, nil
}

// ScanSucceeded implements jobs.CompletionListener. It runs on its own
// goroutine, so a slow webhook never delays a scan. The first scan of an asset
// is skipped, and so is every scan without a new finding at or above the
// threshold.
func (s *Service) ScanSucceeded(scanID, assetID int64) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	settings := s.Settings()
	if !settings.Enabled || len(s.notifiers) == 0 {
		return
	}

	diff, err := s.reports.ScanDiff(ctx, scanID, 0)
	if err != nil {
		s.log.Warn("notifications: diff scan", "scan_id", scanID, "error", err)
		return
	}
	// No earlier succeeded scan means this is the asset's first one; every
	// finding would be "new" and the user asked us not to send that.
	if diff.AgainstScanID == nil {
		return
	}

	counts := countsFrom(diff.Counts.New)
	if countAtOrAbove(counts, settings.Threshold) == 0 {
		return
	}

	summary := Summary{
		AssetID:   assetID,
		AssetName: s.assetName(ctx, assetID),
		ScanID:    scanID,
		Counts:    counts,
		URL:       s.reportURL(assetID),
	}
	for _, notifier := range s.notifiers {
		if !enabledFor(notifier.Name(), settings) {
			continue
		}
		if err := notifier.Notify(ctx, summary); err != nil {
			s.log.Warn("notifications: notify", "notifier", notifier.Name(),
				"scan_id", scanID, "error", err)
		}
	}
}

// SendTest delivers a sample message to the Slack notifier, whether or not the
// setting is enabled. It is the settings modal's "send test" action.
func (s *Service) SendTest(ctx context.Context) error {
	if s.slack == nil {
		return fmt.Errorf("%w: no Slack notifier", ErrUnavailable)
	}
	if !s.SlackConfigured() {
		return ErrNoWebhook
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	summary := Summary{
		AssetName: "Bastion",
		URL:       s.baseURL,
		Test:      true,
	}
	if err := s.slack.Notify(ctx, summary); err != nil {
		return fmt.Errorf("notifications: send test: %w", err)
	}
	return nil
}

// assetName looks the display name up directly; a deleted or missing asset
// still yields a usable message.
func (s *Service) assetName(ctx context.Context, assetID int64) string {
	asset, err := sqlcdb.New(s.db).GetAsset(ctx, assetID)
	if err != nil || asset.DisplayName == "" {
		return fmt.Sprintf("asset %d", assetID)
	}
	return asset.DisplayName
}

// reportURL links to the asset's findings list, the route the UI reads.
func (s *Service) reportURL(assetID int64) string {
	return fmt.Sprintf("%s/findings?asset=%d", s.baseURL, assetID)
}

// readSettings loads the file, falling back to the defaults on any error: a
// hand-edited or half-written file must not stop the server.
func (s *Service) readSettings() Settings {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return DefaultSettings()
	}
	var stored Settings
	if err := decodeSettings(data, &stored); err != nil {
		s.log.Warn("notifications: read settings", "error", err)
		return DefaultSettings()
	}
	if !ValidThreshold(stored.Threshold) {
		stored.Threshold = ThresholdHigh
	}
	return stored
}

// writeSettings stores the non-secret choices. The file holds no credential.
func (s *Service) writeSettings(settings Settings) error {
	data, err := encodeSettings(settings)
	if err != nil {
		return fmt.Errorf("notifications: encode settings: %w", err)
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return fmt.Errorf("notifications: store settings: %w", err)
	}
	return nil
}

// decodeSettings decodes the settings file.
func decodeSettings(data []byte, out *Settings) error {
	return json.Unmarshal(data, out)
}

// encodeSettings marshals the settings with a trailing newline, like the other
// settings files.
func encodeSettings(settings Settings) ([]byte, error) {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ValidThreshold reports whether threshold is one the service accepts.
func ValidThreshold(threshold string) bool {
	return threshold == ThresholdHigh || threshold == ThresholdCritical
}

// ValidateSlackWebhook accepts only an https URL on hooks.slack.com. The
// webhook is a bearer credential, so a plaintext or foreign host is refused
// before it is stored.
func ValidateSlackWebhook(raw string) error {
	if raw == "" {
		return fmt.Errorf("%w: the Slack webhook is empty", ErrInvalid)
	}
	if len(raw) > MaxWebhookLength {
		return fmt.Errorf("%w: the Slack webhook is longer than %d characters",
			ErrInvalid, MaxWebhookLength)
	}
	if err := validateSlackWebhookURL(raw); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

// countsFrom converts the report severity totals.
func countsFrom(totals reports.SeverityTotals) Counts {
	return Counts{
		Critical: totals.Critical,
		High:     totals.High,
		Medium:   totals.Medium,
		Low:      totals.Low,
		Unknown:  totals.Unknown,
	}
}

// countAtOrAbove is how many new findings meet the threshold.
func countAtOrAbove(counts Counts, threshold string) int {
	if threshold == ThresholdCritical {
		return counts.Critical
	}
	return counts.Critical + counts.High
}

// enabledFor reports whether one notifier is on. Slack has its own switch;
// every other notifier follows the master switch, which is what the tests'
// fake relies on.
func enabledFor(name string, settings Settings) bool {
	if name == SlackName {
		return settings.SlackEnabled
	}
	return true
}
