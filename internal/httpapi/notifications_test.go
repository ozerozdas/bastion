package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ozerozdas/bastion/internal/httpapi/gen"
)

// TestNotificationEmailSettings is the #46 API contract for email: defaults
// on port 587, validation of every field, a password that is write-only and
// reported only as configured, and a clear that follows the Slack webhook's
// pattern.
func TestNotificationEmailSettings(t *testing.T) {
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
	if initial.EmailEnabled || initial.SmtpHost != "" || initial.SmtpPort != 587 ||
		initial.SmtpUsername != "" || initial.From != "" || initial.To != "" ||
		initial.EmailPasswordConfigured {
		t.Fatalf("initial email settings = %+v, want off with port 587", initial)
	}

	for _, body := range []map[string]any{
		{"smtp_host": "https://smtp.example.com"},
		{"smtp_host": "smtp.example.com\r\nX-Injected: yes"},
		{"smtp_port": 0},
		{"smtp_port": 70000},
		{"from": "not an address"},
		{"to": "ops@example.com, nope"},
		{"to": " , "},
		{"email_password": "x", "clear_email_password": true},
	} {
		resp = doJSON(t, ts, http.MethodPut, "/api/notifications", body, withBastion(cookie))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("PUT %v status = %d, want %d", body, resp.StatusCode, http.StatusBadRequest)
		}
	}

	resp = doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"email_enabled":  true,
		"smtp_host":      "smtp.example.com",
		"smtp_port":      2525,
		"smtp_username":  "bastion",
		"from":           "bastion@example.com",
		"to":             "ops@example.com, sec@example.com",
		"email_password": "s3cret",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d: %s", resp.StatusCode, http.StatusOK, readBody(t, resp))
	}
	raw := readBody(t, resp)
	if strings.Contains(string(raw), "s3cret") {
		t.Fatal("the response contains the SMTP password")
	}
	var stored gen.NotificationSettings
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("decode stored settings: %v", err)
	}
	if !stored.EmailEnabled || stored.SmtpHost != "smtp.example.com" || stored.SmtpPort != 2525 ||
		stored.SmtpUsername != "bastion" || stored.From != "bastion@example.com" ||
		stored.To != "ops@example.com, sec@example.com" || !stored.EmailPasswordConfigured {
		t.Fatalf("stored email settings = %+v", stored)
	}

	// A merge that omits the email fields leaves them untouched.
	resp = doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"email_enabled": false,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("merge PUT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var merged gen.NotificationSettings
	if err := json.Unmarshal(readBody(t, resp), &merged); err != nil {
		t.Fatalf("decode merged settings: %v", err)
	}
	if merged.EmailEnabled || merged.SmtpHost != "smtp.example.com" || !merged.EmailPasswordConfigured {
		t.Fatalf("merged settings = %+v, want email off but still configured", merged)
	}

	resp = doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"clear_email_password": true,
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var cleared gen.NotificationSettings
	if err := json.Unmarshal(readBody(t, resp), &cleared); err != nil {
		t.Fatalf("decode cleared settings: %v", err)
	}
	if cleared.EmailPasswordConfigured {
		t.Fatal("EmailPasswordConfigured = true after clear")
	}
}

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

// TestNotificationEmailTestWithoutPassword is the #46 test-send mapping: an
// SMTP username with no stored password is a configuration error, so it is a
// 400 with the notifier's own message, not a 502.
func TestNotificationEmailTestWithoutPassword(t *testing.T) {
	ts := newTestServer(t)
	cookie := ts.login(t)

	resp := doJSON(t, ts, http.MethodPut, "/api/notifications", map[string]any{
		"smtp_host":     "smtp.example.com",
		"smtp_username": "bastion",
		"from":          "bastion@example.com",
		"to":            "ops@example.com",
	}, withBastion(cookie))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	resp = doJSON(t, ts, http.MethodPost, "/api/notifications/test", nil, withBastion(cookie))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("test status = %d, want %d: %s", resp.StatusCode, http.StatusBadRequest, readBody(t, resp))
	}
}
