package notifications

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/ozerozdas/bastion/internal/secrets"
)

const (
	// EmailName is the notifier name used in logs and the enabled check.
	EmailName = "email"
	// EmailPasswordKey is the secrets key whose environment fallback is
	// BASTION_SMTP_PASSWORD. It lives in the OS keyring, never in SQLite or an
	// API response.
	EmailPasswordKey = "smtp-password"
	// DefaultSMTPPort is the submission port; a fresh install uses it.
	DefaultSMTPPort = 587

	maxEmailAddresses    = 50
	maxHeaderValue       = 512
	maxSubjectAssetRunes = 120
)

var (
	// ErrEmailNotConfigured means the SMTP host, sender or recipients are
	// missing, so there is nowhere to send a message.
	ErrEmailNotConfigured = errors.New("email notifications are not configured")
	// ErrNoEmailPassword means an SMTP username is set without a stored
	// password, so authentication cannot happen.
	ErrNoEmailPassword = errors.New("no SMTP password is configured")
)

// Email sends the scan summary over SMTP submission with a required STARTTLS
// upgrade. There is deliberately no plain-text fallback and no implicit-TLS
// port 465 support: the connection is upgraded before any credential or
// message crosses it.
type Email struct {
	secrets  secrets.Store
	settings func() Settings
	timeout  time.Duration
	// TLSConfig replaces the system roots. Tests set it to trust the
	// in-process server's self-signed certificate; ServerName is always the
	// configured host.
	TLSConfig *tls.Config
}

// NewEmail returns an Email notifier that reads the current settings on every
// send, so a changed host or password takes effect immediately.
func NewEmail(store secrets.Store, settings func() Settings, timeout time.Duration) *Email {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Email{secrets: store, settings: settings, timeout: timeout}
}

// Name implements Notifier.
func (*Email) Name() string { return EmailName }

// Notify sends one plain-text message. The SMTP server must advertise STARTTLS
// and complete the upgrade; a server that does not is refused before any
// message data is written. Authentication is PLAIN and only after the upgrade.
func (e *Email) Notify(ctx context.Context, summary Summary) error {
	settings := e.settings()
	if settings.SMTPHost == "" || settings.From == "" || settings.To == "" {
		return ErrEmailNotConfigured
	}

	from, err := parseEmailAddress(settings.From, "sender")
	if err != nil {
		return err
	}
	recipients, err := parseEmailAddressList(settings.To)
	if err != nil {
		return err
	}
	port := settings.SMTPPort
	if port == 0 {
		port = DefaultSMTPPort
	}
	if !ValidSMTPPort(port) {
		return fmt.Errorf("%w: the SMTP port is out of range", ErrInvalid)
	}

	password := ""
	if settings.SMTPUsername != "" {
		password, err = e.secrets.Get(EmailPasswordKey)
		if err != nil && !errors.Is(err, secrets.ErrNotFound) {
			return fmt.Errorf("read SMTP password: %w", err)
		}
		if password == "" {
			return ErrNoEmailPassword
		}
	}

	deadline := time.Now().Add(e.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	addr := net.JoinHostPort(settings.SMTPHost, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: e.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connect to SMTP server %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set SMTP deadline: %w", err)
	}

	client, err := smtp.NewClient(conn, settings.SMTPHost)
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer func() { _ = client.Close() }()

	supported, _ := client.Extension("STARTTLS")
	if !supported {
		return fmt.Errorf("SMTP server %s does not advertise STARTTLS; refusing to send in plain text",
			settings.SMTPHost)
	}
	if err := client.StartTLS(e.tlsConfig(settings.SMTPHost)); err != nil {
		return fmt.Errorf("SMTP STARTTLS: %w", err)
	}

	if settings.SMTPUsername != "" {
		if err := client.Auth(smtp.PlainAuth("", settings.SMTPUsername, password, settings.SMTPHost)); err != nil {
			// Keep the server's reply text out of the log: it is remote input.
			var status *textproto.Error
			if errors.As(err, &status) {
				return fmt.Errorf("SMTP authentication failed with status %d", status.Code)
			}
			return errors.New("SMTP authentication failed")
		}
	}

	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	for _, recipient := range recipients {
		if err := client.Rcpt(recipient.Address); err != nil {
			return fmt.Errorf("SMTP RCPT TO: %w", err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	if _, err := io.WriteString(writer, buildEmailMessage(from, recipients, summary)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("SMTP QUIT: %w", err)
	}
	return nil
}

// tlsConfig builds the upgrade config. ServerName is the configured host, so
// the certificate must match it; tests inject RootCAs through TLSConfig.
func (e *Email) tlsConfig(host string) *tls.Config {
	config := &tls.Config{ServerName: host}
	if e.TLSConfig != nil {
		config = e.TLSConfig.Clone()
		config.ServerName = host
	}
	return config
}

// buildEmailMessage renders the headers and plain-text body. Every
// scanner-derived value that reaches a header is stripped of CR and LF first,
// so an asset named "../\r\nBcc: attacker" cannot add a header.
func buildEmailMessage(from *mail.Address, recipients []*mail.Address, summary Summary) string {
	to := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		to = append(to, formatAddress(recipient))
	}

	subject := emailSubject(summary)
	if !isASCII(subject) {
		subject = mime.QEncoding.Encode("utf-8", subject)
	}

	var body strings.Builder
	writer := quotedprintable.NewWriter(&body)
	_, _ = writer.Write([]byte(emailBody(summary)))
	_ = writer.Close()

	headers := []string{
		"From: " + sanitizeHeader(formatAddress(from)),
		"To: " + sanitizeHeader(strings.Join(to, ", ")),
		"Subject: " + subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: " + messageID(from),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body.String()
}

// emailSubject is the subject line: the count of critical and high findings
// and the asset, or a fixed line for the settings modal's test message.
func emailSubject(summary Summary) string {
	if summary.Test {
		return "bastion: test notification"
	}
	count := summary.Counts.Critical + summary.Counts.High
	asset := truncateRunes(sanitizeHeader(summary.AssetName), maxSubjectAssetRunes)
	return fmt.Sprintf("bastion: %d new critical/high findings in %s", count, asset)
}

// emailBody is the plain-text message: the per-severity counts of the new
// findings and a link back to the asset.
func emailBody(summary Summary) string {
	var body strings.Builder
	if summary.Test {
		body.WriteString("Bastion test notification: email is configured correctly.\r\n")
		if summary.URL != "" {
			body.WriteString("\r\n" + summary.URL + "\r\n")
		}
		return body.String()
	}

	fmt.Fprintf(&body, "Bastion found new findings in %s (scan %d).\r\n\r\n",
		sanitizeText(summary.AssetName), summary.ScanID)
	written := false
	for _, count := range []struct {
		n     int
		label string
	}{
		{summary.Counts.Critical, "Critical"},
		{summary.Counts.High, "High"},
		{summary.Counts.Medium, "Medium"},
		{summary.Counts.Low, "Low"},
		{summary.Counts.Unknown, "Unknown"},
	} {
		if count.n > 0 {
			fmt.Fprintf(&body, "%s: %d\r\n", count.label, count.n)
			written = true
		}
	}
	if !written {
		body.WriteString("No new findings.\r\n")
	}
	if summary.URL != "" {
		body.WriteString("\r\n" + summary.URL + "\r\n")
	}
	return body.String()
}

// messageID builds a unique RFC 5322 message id. The domain comes from the
// sender, falling back to bastion.local for a local-only address.
func messageID(from *mail.Address) string {
	domain := "bastion.local"
	if at := strings.LastIndex(from.Address, "@"); at >= 0 && at < len(from.Address)-1 {
		domain = sanitizeHeader(from.Address[at+1:])
	}
	return fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), randomToken(), domain)
}

// randomToken is a short random hex string for the message id.
func randomToken() string {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "0"
	}
	return hex.EncodeToString(buf[:])
}

// sanitizeHeader strips CR and LF from a value that goes into a header. This
// is the header-injection guard, applied at send time as well as the address
// validation at save time.
func sanitizeHeader(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "").Replace(value))
}

// sanitizeText keeps a scanner-derived value on one line in the body.
func sanitizeText(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(value))
}

// truncateRunes caps value at limit runes, marking the cut with an ellipsis.
func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "\u2026"
}

// isASCII reports whether value needs no MIME word encoding.
func isASCII(value string) bool {
	for _, r := range value {
		if r < ' ' || r > '~' {
			return false
		}
	}
	return true
}

// ValidateSMTPHost accepts a hostname or IP literal, trimmed. A scheme, path
// or whitespace is refused.
func ValidateSMTPHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	switch {
	case host == "":
		return "", fmt.Errorf("%w: the SMTP host is empty", ErrInvalid)
	case len(host) > 255:
		return "", fmt.Errorf("%w: the SMTP host is longer than 255 characters", ErrInvalid)
	case strings.Contains(host, "://"):
		return "", fmt.Errorf("%w: the SMTP host must be a hostname or IP, not a URL", ErrInvalid)
	case !validSMTPHost(host):
		return "", fmt.Errorf("%w: the SMTP host is not a valid hostname or IP", ErrInvalid)
	}
	return host, nil
}

// validSMTPHost accepts an IP literal or a dotted hostname.
func validSMTPHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
			if !ok || (c == '-' && (i == 0 || i == len(label)-1)) {
				return false
			}
		}
	}
	return true
}

// ValidSMTPPort reports whether port is a usable TCP port.
func ValidSMTPPort(port int) bool {
	return port >= 1 && port <= 65535
}

// normalizeSMTPUsername trims the username and refuses control characters.
func normalizeSMTPUsername(raw string) (string, error) {
	username := strings.TrimSpace(raw)
	if len(username) > maxHeaderValue {
		return "", fmt.Errorf("%w: the SMTP username is longer than %d characters",
			ErrInvalid, maxHeaderValue)
	}
	if strings.ContainsAny(username, "\r\n") {
		return "", fmt.Errorf("%w: the SMTP username contains a line break", ErrInvalid)
	}
	return username, nil
}

// ValidateEmailPassword refuses an empty password and line breaks.
func ValidateEmailPassword(raw string) error {
	switch {
	case raw == "":
		return fmt.Errorf("%w: the SMTP password is empty", ErrInvalid)
	case len(raw) > maxHeaderValue:
		return fmt.Errorf("%w: the SMTP password is longer than %d characters",
			ErrInvalid, maxHeaderValue)
	case strings.ContainsAny(raw, "\r\n"):
		return fmt.Errorf("%w: the SMTP password contains a line break", ErrInvalid)
	}
	return nil
}

// formatAddress renders an address for storage and for a header. A bare
// address stays bare; a display name keeps net/mail's quoting.
func formatAddress(address *mail.Address) string {
	if address.Name == "" {
		return address.Address
	}
	return address.String()
}

// normalizeEmailAddress validates one address and returns its canonical form.
func normalizeEmailAddress(raw, field string) (string, error) {
	address, err := parseEmailAddress(raw, field)
	if err != nil {
		return "", err
	}
	return formatAddress(address), nil
}

// parseEmailAddress parses one RFC 5322 address, refusing embedded line
// breaks even if net/mail would tolerate them.
func parseEmailAddress(raw, field string) (*mail.Address, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: the %s address is empty", ErrInvalid, field)
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return nil, fmt.Errorf("%w: the %s address contains a line break", ErrInvalid, field)
	}
	address, err := mail.ParseAddress(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: the %s address is not valid", ErrInvalid, field)
	}
	return address, nil
}

// parseEmailAddressList parses the comma-separated recipient list. At least
// one address is required; empty entries are ignored so a trailing comma is
// harmless.
func parseEmailAddressList(raw string) ([]*mail.Address, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: at least one recipient address is required", ErrInvalid)
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return nil, fmt.Errorf("%w: the recipient address contains a line break", ErrInvalid)
	}
	addresses, err := mail.ParseAddressList(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: the recipient address list is not valid", ErrInvalid)
	}
	if len(addresses) > maxEmailAddresses {
		return nil, fmt.Errorf("%w: at most %d recipient addresses are allowed",
			ErrInvalid, maxEmailAddresses)
	}
	return addresses, nil
}

// normalizeEmailAddressList validates the recipients and returns them joined
// in canonical form, suitable for storing and for the To header.
func normalizeEmailAddressList(raw string) (string, error) {
	addresses, err := parseEmailAddressList(raw)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(addresses))
	for _, address := range addresses {
		parts = append(parts, formatAddress(address))
	}
	return strings.Join(parts, ", "), nil
}
