package notifications

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ozerozdas/bastion/internal/secrets"
)

func TestEmailNotifiesOverSTARTTLS(t *testing.T) {
	server := newFakeSMTPServer(t, true)

	store := secrets.NewMemoryStore()
	if err := store.Set(EmailPasswordKey, "s3cret"); err != nil {
		t.Fatalf("Set password: %v", err)
	}
	notifier := &Email{
		secrets: store,
		settings: func() Settings {
			return Settings{
				EmailEnabled: true,
				SMTPHost:     server.host,
				SMTPPort:     server.port,
				SMTPUsername: "bastion",
				From:         "bastion@example.com",
				To:           "ops@example.com, sec@example.com",
			}
		},
		timeout:   5 * time.Second,
		TLSConfig: &tls.Config{RootCAs: server.roots},
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

	messages := server.messages()
	if len(messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(messages))
	}
	message := messages[0]
	for _, want := range []string{
		"From: bastion@example.com",
		"To: ops@example.com, sec@example.com",
		"Subject: bastion: 3 new critical/high findings in payments-api",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Date: ",
		"Message-ID: <",
		"Critical: 1",
		"High: 2",
		"http://127.0.0.1:1234/findings?asset=3D7",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("message does not contain %q:\n%s", want, message)
		}
	}
	if !server.authenticated() {
		t.Error("server did not see AUTH PLAIN")
	}
	if server.authBeforeTLS() {
		t.Error("AUTH arrived before the STARTTLS upgrade")
	}
}

func TestEmailRefusesServerWithoutSTARTTLS(t *testing.T) {
	server := newFakeSMTPServer(t, false)

	notifier := &Email{
		secrets: secrets.NewMemoryStore(),
		settings: func() Settings {
			return Settings{
				SMTPHost: server.host,
				SMTPPort: server.port,
				From:     "bastion@example.com",
				To:       "ops@example.com",
			}
		},
		timeout:   2 * time.Second,
		TLSConfig: &tls.Config{RootCAs: server.roots},
	}

	err := notifier.Notify(t.Context(), Summary{AssetName: "payments-api"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("error = %v, want a STARTTLS refusal", err)
	}
	if messages := server.messages(); len(messages) != 0 {
		t.Fatalf("messages = %d, want 0: nothing may be sent without TLS", len(messages))
	}
}

func TestEmailStripsHeaderInjection(t *testing.T) {
	server := newFakeSMTPServer(t, true)

	notifier := &Email{
		secrets: secrets.NewMemoryStore(),
		settings: func() Settings {
			return Settings{
				SMTPHost: server.host,
				SMTPPort: server.port,
				From:     "bastion@example.com",
				To:       "ops@example.com",
			}
		},
		timeout:   5 * time.Second,
		TLSConfig: &tls.Config{RootCAs: server.roots},
	}

	err := notifier.Notify(t.Context(), Summary{
		AssetName: "payments\r\nBcc: attacker@example.com",
		ScanID:    7,
		Counts:    Counts{Critical: 1},
		URL:       "http://127.0.0.1:1234/findings?asset=1",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}

	messages := server.messages()
	if len(messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(messages))
	}
	header, _, found := strings.Cut(messages[0], "\r\n\r\n")
	if !found {
		t.Fatal("message has no header/body separator")
	}
	for _, line := range strings.Split(header, "\r\n") {
		if strings.HasPrefix(line, "Bcc:") {
			t.Fatalf("injected header survived:\n%s", header)
		}
	}
	if !strings.Contains(header, "Subject: bastion: 1 new critical/high findings in paymentsBcc: attacker@example.com") {
		t.Errorf("subject does not contain the stripped asset name:\n%s", header)
	}
}

func TestEmailRefusesUntrustedCertificate(t *testing.T) {
	server := newFakeSMTPServer(t, true)

	notifier := &Email{
		secrets: secrets.NewMemoryStore(),
		settings: func() Settings {
			return Settings{
				SMTPHost: server.host,
				SMTPPort: server.port,
				From:     "bastion@example.com",
				To:       "ops@example.com",
			}
		},
		timeout:   2 * time.Second,
		TLSConfig: &tls.Config{RootCAs: x509.NewCertPool()},
	}

	if err := notifier.Notify(t.Context(), Summary{AssetName: "payments-api"}); err == nil {
		t.Fatal("Notify succeeded with an untrusted certificate")
	}
	if messages := server.messages(); len(messages) != 0 {
		t.Fatalf("messages = %d, want 0: nothing may be sent after a failed handshake", len(messages))
	}
}

func TestEmailRequiresPasswordWhenUsernameIsSet(t *testing.T) {
	notifier := &Email{
		secrets: secrets.NewMemoryStore(),
		settings: func() Settings {
			return Settings{
				SMTPHost:     "127.0.0.1",
				SMTPPort:     DefaultSMTPPort,
				SMTPUsername: "bastion",
				From:         "bastion@example.com",
				To:           "ops@example.com",
			}
		},
		timeout: time.Second,
	}
	err := notifier.Notify(t.Context(), Summary{AssetName: "a"})
	if !errors.Is(err, ErrNoEmailPassword) {
		t.Fatalf("error = %v, want ErrNoEmailPassword", err)
	}
}

func TestEmailNotConfiguredWithoutHost(t *testing.T) {
	notifier := NewEmail(secrets.NewMemoryStore(), func() Settings { return Settings{} }, time.Second)
	err := notifier.Notify(t.Context(), Summary{AssetName: "a"})
	if !errors.Is(err, ErrEmailNotConfigured) {
		t.Fatalf("error = %v, want ErrEmailNotConfigured", err)
	}
}

// fakeSMTPServer is a minimal ESMTP server: EHLO, optional STARTTLS, AUTH
// PLAIN, MAIL, RCPT, DATA and QUIT. It records the message bodies it receives.
type fakeSMTPServer struct {
	host     string
	port     int
	roots    *x509.CertPool
	startTLS bool
	cert     tls.Certificate

	mu         sync.Mutex
	received   []string
	authed     bool
	preTLSAuth bool
}

func newFakeSMTPServer(t *testing.T, startTLS bool) *fakeSMTPServer {
	t.Helper()

	cert, roots := newTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi port: %v", err)
	}

	server := &fakeSMTPServer{
		host:     host,
		port:     port,
		roots:    roots,
		startTLS: startTLS,
		cert:     cert,
	}
	go server.serve(listener)
	return server
}

func (s *fakeSMTPServer) serve(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	write := func(line string) bool {
		if _, err := writer.WriteString(line + "\r\n"); err != nil {
			return false
		}
		return writer.Flush() == nil
	}

	if !write("220 fake ESMTP") {
		return
	}

	dataMode := false
	tlsActive := false
	var message strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		if dataMode {
			if line == "." {
				dataMode = false
				s.mu.Lock()
				s.received = append(s.received, message.String())
				s.mu.Unlock()
				if !write("250 2.0.0 OK: queued") {
					return
				}
				continue
			}
			message.WriteString(line + "\r\n")
			continue
		}

		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			lines := []string{"250-fake"}
			if s.startTLS {
				lines = append(lines, "250-STARTTLS")
			}
			lines = append(lines, "250 AUTH PLAIN")
			for _, reply := range lines {
				if !write(reply) {
					return
				}
			}
		case strings.HasPrefix(upper, "HELO"):
			if !write("250 fake") {
				return
			}
		case upper == "STARTTLS":
			if !s.startTLS {
				if !write("502 5.5.1 STARTTLS not supported") {
					return
				}
				continue
			}
			if !write("220 2.0.0 Ready to start TLS") {
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			tlsActive = true
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			reader = bufio.NewReader(conn)
			writer = bufio.NewWriter(conn)
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			s.mu.Lock()
			s.authed = true
			if !tlsActive {
				s.preTLSAuth = true
			}
			s.mu.Unlock()
			if !write("235 2.7.0 Authentication successful") {
				return
			}
		case strings.HasPrefix(upper, "MAIL FROM:"):
			if !write("250 2.1.0 OK") {
				return
			}
		case strings.HasPrefix(upper, "RCPT TO:"):
			if !write("250 2.1.5 OK") {
				return
			}
		case upper == "DATA":
			message.Reset()
			if !write("354 End data with <CR><LF>.<CR><LF>") {
				return
			}
			dataMode = true
		case upper == "RSET":
			if !write("250 2.0.0 OK") {
				return
			}
		case upper == "QUIT":
			_ = write("221 2.0.0 Bye")
			return
		default:
			if !write("502 5.5.2 Command not implemented") {
				return
			}
		}
	}
}

func (s *fakeSMTPServer) messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.received...)
}

func (s *fakeSMTPServer) authenticated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authed
}

func (s *fakeSMTPServer) authBeforeTLS() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preTLSAuth
}

// newTestCertificate generates a throwaway self-signed certificate for
// 127.0.0.1 and a pool that trusts it, so the test never touches the system
// roots.
func newTestCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bastion-test-smtp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, roots
}
