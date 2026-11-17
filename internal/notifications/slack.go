package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/secrets"
)

const (
	// SlackName is the notifier name used in logs and the enabled check.
	SlackName = "slack"
	// SlackWebhookKey is the secrets key whose environment fallback is
	// BASTION_SLACK_WEBHOOK. The URL is a bearer credential, so it lives in
	// the OS keyring, never in SQLite or an API response.
	SlackWebhookKey = "slack-webhook"

	slackHost = "hooks.slack.com"
)

// Slack posts a short message to a Slack incoming webhook. The webhook URL is
// read from the secret store on every send, so clearing or replacing it takes
// effect immediately.
type Slack struct {
	secrets secrets.Store
	client  *http.Client
	// validate guards the stored URL before a request is made. Tests replace
	// it so an httptest server can receive the payload.
	validate func(string) error
}

// NewSlack returns a Slack notifier. A nil client gets a 10s timeout.
func NewSlack(store secrets.Store, client *http.Client) *Slack {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Slack{secrets: store, client: client, validate: validateSlackWebhookURL}
}

// Name implements Notifier.
func (*Slack) Name() string { return SlackName }

// Notify posts one message. Slack answers "ok" with HTTP 200; any other status
// is an error, which the caller logs without failing the scan.
func (s *Slack) Notify(ctx context.Context, summary Summary) error {
	webhook, err := s.secrets.Get(SlackWebhookKey)
	if err != nil || webhook == "" {
		return fmt.Errorf("no Slack webhook: %w", ErrNoWebhook)
	}
	if err := s.validate(webhook); err != nil {
		return err
	}

	payload, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: slackMessage(summary)})
	if err != nil {
		return fmt.Errorf("encode Slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build Slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("post Slack message: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain a little so the connection is reusable; the body is not parsed.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("Slack returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// slackMessage is the user-facing text: the asset, the new counts and the
// report link. A test message has no counts.
func slackMessage(summary Summary) string {
	if summary.Test {
		message := "Bastion test notification: Slack is configured correctly."
		if summary.URL != "" {
			message += " " + summary.URL
		}
		return message
	}

	parts := make([]string, 0, 5)
	for _, count := range []struct {
		n     int
		label string
	}{
		{summary.Counts.Critical, "critical"},
		{summary.Counts.High, "high"},
		{summary.Counts.Medium, "medium"},
		{summary.Counts.Low, "low"},
		{summary.Counts.Unknown, "unknown"},
	} {
		if count.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count.n, count.label))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "no new findings")
	}

	message := fmt.Sprintf("Bastion: %s — %s new findings (scan %d)",
		summary.AssetName, strings.Join(parts, ", "), summary.ScanID)
	if summary.URL != "" {
		message += "\n" + summary.URL
	}
	return message
}

// validateSlackWebhookURL accepts only a postable Slack incoming webhook:
// https on hooks.slack.com with the /services path Slack issues.
func validateSlackWebhookURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("the Slack webhook is not a valid URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("the Slack webhook must use https")
	}
	if !strings.EqualFold(parsed.Host, slackHost) {
		return fmt.Errorf("the Slack webhook must be on %s", slackHost)
	}
	if !strings.HasPrefix(parsed.Path, "/services/") {
		return errors.New("the Slack webhook path must start with /services/")
	}
	return nil
}
