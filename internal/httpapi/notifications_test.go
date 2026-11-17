package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// TestNotificationSettingsContract is the #44/#45 API contract: defaults are
// off with a high threshold, a PUT merges, an invalid webhook is a 400, the
// webhook is never returned, and a test send without one is a 400.
func TestNotificationSettingsContract(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := ts.do(t, http.MethodGet, "/api/notifications", withCookie(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var initial gen.NotificationSettings
	if err := json.Unmarshal(readBody(t, resp), &initial); err != nil {
		t.Fatalf("decode initial settings: %v", err)
	}
	if initial.Enabled || initial.SlackEnabled || initial.SlackConfigured ||
		initial.Threshold != gen.NotificationThresholdHigh {
		t.Fatalf("initial settings = %+v, want all off with threshold high", initial)
	}

	// Invalid webhook: not https on hooks.slack.com.
	resp = doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"slack_webhook": "http://example.com/services/T/B/x",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid webhook status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// Set and clear together is rejected.
	resp = doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"slack_webhook":       "https://hooks.slack.com/services/T/B/x",
		"clear_slack_webhook": true,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("set+clear status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// A valid PUT stores the choices and reports the webhook as configured
	// without returning it.
	resp = doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"enabled":       true,
		"threshold":     "critical",
		"slack_enabled": true,
		"slack_webhook": "https://hooks.slack.com/services/T000/B000/secret",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	var stored gen.NotificationSettings
	if err := json.Unmarshal(readBody(t, resp), &stored); err != nil {
		t.Fatalf("decode stored settings: %v", err)
	}
	if !stored.Enabled || !stored.SlackEnabled || !stored.SlackConfigured ||
		stored.Threshold != gen.NotificationThresholdCritical {
		t.Fatalf("stored settings = %+v", stored)
	}

	// A body without the webhook leaves it configured (the response never
	// carries the URL).
	resp = doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"enabled": false,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("merge PUT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var merged gen.NotificationSettings
	if err := json.Unmarshal(readBody(t, resp), &merged); err != nil {
		t.Fatalf("decode merged settings: %v", err)
	}
	if merged.Enabled || !merged.SlackConfigured {
		t.Fatalf("merged settings = %+v, want enabled false and Slack still configured", merged)
	}

	// Clearing removes it.
	resp = doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"clear_slack_webhook": true,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var cleared gen.NotificationSettings
	if err := json.Unmarshal(readBody(t, resp), &cleared); err != nil {
		t.Fatalf("decode cleared settings: %v", err)
	}
	if cleared.SlackConfigured {
		t.Fatal("SlackConfigured = true after clear")
	}

	// With no webhook the test endpoint answers 400 and never reaches Slack.
	resp = doJSON(t, ts, http.MethodPost, "/api/notifications/test", nil, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("test status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}
