package notifications

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/findings"
	"github.com/ozerozdas/bastion/internal/reports"
	"github.com/ozerozdas/bastion/internal/secrets"
	"github.com/ozerozdas/bastion/internal/store"
)

// fakeNotifier records calls and returns a fixed error.
type fakeNotifier struct {
	mu        sync.Mutex
	summaries []Summary
	err       error
}

func (f *fakeNotifier) Name() string { return "fake" }

func (f *fakeNotifier) Notify(_ context.Context, summary Summary) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.summaries = append(f.summaries, summary)
	return f.err
}

func (f *fakeNotifier) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.summaries)
}

// fixture seeds one asset and two succeeded scans. The first has a critical
// finding; the second keeps it and adds a high one.
type fixture struct {
	service *Service
	db      *sql.DB
	notify  *fakeNotifier
	asset   findings.Asset
	first   int64
	second  int64
	failed  int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	asset, err := store.GetOrCreateAsset(t.Context(), db, findings.Asset{
		Kind: findings.AssetKindPath, Ref: "/tmp/notifications", DisplayName: "Notifications",
	})
	if err != nil {
		t.Fatalf("GetOrCreateAsset: %v", err)
	}

	reportService, err := reports.NewService(db)
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}
	notify := &fakeNotifier{}
	service, err := New(Config{
		DataDir:   t.TempDir(),
		DB:        db,
		Secrets:   secrets.NewMemoryStore(),
		Reports:   reportService,
		BaseURL:   "http://127.0.0.1:1234",
		Notifiers: []Notifier{notify},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	critical := newFinding(asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical)
	high := newFinding(asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh)

	return &fixture{
		service: service,
		db:      db,
		notify:  notify,
		asset:   asset,
		first:   seedScan(t, db, asset.ID, store.ScanStatusSucceeded, critical),
		second:  seedScan(t, db, asset.ID, store.ScanStatusSucceeded, critical, high),
		failed:  seedScan(t, db, asset.ID, store.ScanStatusFailed, critical),
	}
}

// enable turns the master switch on with a threshold.
func (f *fixture) enable(t *testing.T, threshold string) {
	t.Helper()
	enabled := true
	if _, err := f.service.Update(UpdateInput{Enabled: &enabled, Threshold: &threshold}); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func seedScan(t *testing.T, db *sql.DB, assetID int64, status string, list ...findings.Finding) int64 {
	t.Helper()
	scanID, err := store.StartScan(t.Context(), db, assetID, store.ScanTriggerCLI)
	if err != nil {
		t.Fatalf("StartScan: %v", err)
	}
	result := store.ScanResult{Status: status, FinishedAt: time.Now().UTC(), Findings: list}
	if status == store.ScanStatusFailed {
		result.Error = "scanner failed"
	}
	if err := store.SaveScanResult(t.Context(), db, scanID, result); err != nil {
		t.Fatalf("SaveScanResult: %v", err)
	}
	return scanID
}

func newFinding(assetID int64, kind findings.Type, ruleID string, severity findings.Severity) findings.Finding {
	finding := findings.Finding{
		AssetID:     assetID,
		Type:        kind,
		RuleID:      ruleID,
		Severity:    severity,
		Title:       "example finding " + ruleID,
		PackageName: "example",
		Ecosystem:   "go",
		Scanner:     "trivy",
		Occurrences: 1,
	}
	finding.Fingerprint = findings.Fingerprint(assetID, finding)
	return finding
}

func TestScanSucceededNotifiesOnceForQualifyingScan(t *testing.T) {
	f := newFixture(t)
	f.enable(t, ThresholdHigh)

	f.service.ScanSucceeded(f.second, f.asset.ID)
	if got := f.notify.calls(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	summary := f.notify.summaries[0]
	if summary.AssetName != "Notifications" {
		t.Errorf("AssetName = %q, want Notifications", summary.AssetName)
	}
	if summary.ScanID != f.second {
		t.Errorf("ScanID = %d, want %d", summary.ScanID, f.second)
	}
	if summary.Counts.High != 1 || summary.Counts.Critical != 0 {
		t.Errorf("Counts = %+v, want high 1 and critical 0", summary.Counts)
	}
	if summary.URL != "http://127.0.0.1:1234/findings?asset="+itoa(f.asset.ID) {
		t.Errorf("URL = %q", summary.URL)
	}
}

func TestScanSucceededSkipsFirstScan(t *testing.T) {
	f := newFixture(t)
	f.enable(t, ThresholdHigh)

	f.service.ScanSucceeded(f.first, f.asset.ID)
	if got := f.notify.calls(); got != 0 {
		t.Fatalf("calls = %d, want 0 on the first scan", got)
	}
}

func TestScanSucceededSkipsNoNewFindings(t *testing.T) {
	f := newFixture(t)
	f.enable(t, ThresholdHigh)
	// Diff the first scan against nothing and then the second against the
	// first: the second adds only a high finding, so make the comparison a
	// scan that adds nothing.
	same := seedScan(t, f.db, f.asset.ID, store.ScanStatusSucceeded,
		newFinding(f.asset.ID, findings.TypeVulnerability, "CVE-2026-0001", findings.SeverityCritical),
		newFinding(f.asset.ID, findings.TypeSecret, "generic-api-key", findings.SeverityHigh))

	f.service.ScanSucceeded(same, f.asset.ID)
	if got := f.notify.calls(); got != 0 {
		t.Fatalf("calls = %d, want 0 when no new finding meets the threshold", got)
	}
}

func TestScanSucceededSkipsBelowThreshold(t *testing.T) {
	f := newFixture(t)
	f.enable(t, ThresholdCritical)

	// The second scan adds a high finding; critical is persisting, so nothing
	// meets the critical-only threshold.
	f.service.ScanSucceeded(f.second, f.asset.ID)
	if got := f.notify.calls(); got != 0 {
		t.Fatalf("calls = %d, want 0 below the critical threshold", got)
	}
}

func TestScanSucceededSkipsFailedScan(t *testing.T) {
	f := newFixture(t)
	f.enable(t, ThresholdHigh)

	f.service.ScanSucceeded(f.failed, f.asset.ID)
	if got := f.notify.calls(); got != 0 {
		t.Fatalf("calls = %d, want 0 for a failed scan", got)
	}
}

func TestScanSucceededLogsNotifierFailure(t *testing.T) {
	f := newFixture(t)
	f.enable(t, ThresholdHigh)
	f.notify.err = errors.New("webhook down")

	f.service.ScanSucceeded(f.second, f.asset.ID)
	if got := f.notify.calls(); got != 1 {
		t.Fatalf("calls = %d, want 1: a notifier failure is logged, not retried", got)
	}
}

func TestSlackNotifiesWithPayload(t *testing.T) {
	var (
		mu       sync.Mutex
		requests int
		payload  struct {
			Text string `json:"text"`
		}
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		mu.Lock()
		requests++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	store := secrets.NewMemoryStore()
	if err := store.Set(SlackWebhookKey, server.URL+"/services/T000/B000/secret"); err != nil {
		t.Fatalf("Set webhook: %v", err)
	}
	notifier := &Slack{
		secrets: store,
		client:  server.Client(),
		// The httptest URL is loopback http; only the test skips the host
		// check, which TestValidateSlackWebhook covers.
		validate: func(string) error { return nil },
	}

	err := notifier.Notify(t.Context(), Summary{
		AssetName: "payments-api",
		ScanID:    42,
		Counts:    Counts{Critical: 1, High: 2},
		URL:       "http://127.0.0.1:1234/findings?asset=7",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
	for _, want := range []string{"payments-api", "1 critical", "2 high", "scan 42", "http://127.0.0.1:1234/findings?asset=7"} {
		if !strings.Contains(payload.Text, want) {
			t.Errorf("message %q does not contain %q", payload.Text, want)
		}
	}
}

func TestSlackRequiresWebhook(t *testing.T) {
	notifier := NewSlack(secrets.NewMemoryStore(), nil)
	err := notifier.Notify(t.Context(), Summary{AssetName: "a"})
	if !errors.Is(err, ErrNoWebhook) {
		t.Fatalf("error = %v, want ErrNoWebhook", err)
	}
}

func TestSlackRejectsNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	store := secrets.NewMemoryStore()
	if err := store.Set(SlackWebhookKey, server.URL+"/services/T/B/x"); err != nil {
		t.Fatalf("Set webhook: %v", err)
	}
	notifier := &Slack{secrets: store, client: server.Client(), validate: func(string) error { return nil }}
	if err := notifier.Notify(t.Context(), Summary{AssetName: "a"}); err == nil {
		t.Fatal("Notify succeeded, want a non-2xx error")
	}
}

func TestValidateSlackWebhook(t *testing.T) {
	for _, tc := range []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "valid", url: "https://hooks.slack.com/services/T000/B000/secret"},
		{name: "http", url: "http://hooks.slack.com/services/T000/B000/secret", wantErr: true},
		{name: "foreign host", url: "https://example.com/services/T/B/x", wantErr: true},
		{name: "wrong path", url: "https://hooks.slack.com/other/T/B/x", wantErr: true},
		{name: "empty", url: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSlackWebhook(tc.url)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateSlackWebhook(%q) error = %v, wantErr %v", tc.url, err, tc.wantErr)
			}
		})
	}
}

func TestUpdateValidatesAndStores(t *testing.T) {
	service, err := New(Config{
		DataDir:   t.TempDir(),
		DB:        newDB(t),
		Secrets:   secrets.NewMemoryStore(),
		Reports:   newReports(t),
		Notifiers: []Notifier{&fakeNotifier{}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	enabled := true
	threshold := ThresholdCritical
	slack := true
	webhook := "https://hooks.slack.com/services/T000/B000/secret"
	settings, err := service.Update(UpdateInput{
		Enabled: &enabled, Threshold: &threshold, SlackEnabled: &slack, SlackWebhook: &webhook,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !settings.Enabled || settings.Threshold != ThresholdCritical || !settings.SlackEnabled {
		t.Fatalf("settings = %+v", settings)
	}
	if !service.SlackConfigured() {
		t.Fatal("SlackConfigured = false, want true")
	}

	bad := "http://hooks.slack.com/services/T/B/x"
	if _, err := service.Update(UpdateInput{SlackWebhook: &bad}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid webhook error = %v, want ErrInvalid", err)
	}
	if _, err := service.Update(UpdateInput{ClearSlackWebhook: true}); err != nil {
		t.Fatalf("clear webhook: %v", err)
	}
	if service.SlackConfigured() {
		t.Fatal("SlackConfigured = true after clear")
	}
}

// newDB and newReports keep TestUpdateValidatesAndStores small.
func newDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "bastion.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newReports(t *testing.T) *reports.Service {
	t.Helper()
	service, err := reports.NewService(newDB(t))
	if err != nil {
		t.Fatalf("reports.NewService: %v", err)
	}
	return service
}

// itoa avoids importing strconv for one call.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
