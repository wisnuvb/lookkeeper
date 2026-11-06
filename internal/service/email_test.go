package service

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wisnuvb/lockkeeper/internal/collector"
	"github.com/wisnuvb/lockkeeper/internal/config"
	"github.com/wisnuvb/lockkeeper/internal/redact"
	"github.com/wisnuvb/lockkeeper/internal/secret"
	"github.com/wisnuvb/lockkeeper/internal/testutil/fakesmtp"
)

const smtpPasswordCanary = "SMTP-PASSWORD-canary-51d2"

// emailService builds a service whose email channel talks to srv over implicit
// TLS, trusting only that server's throwaway certificate through ca_file.
func emailService(t *testing.T, srv *fakesmtp.Server, log io.Writer, pw string) *Service {
	t.Helper()
	yaml := testYAML + `    email:
      host: ` + srv.Host + `
      port: ` + strconv.Itoa(srv.Port) + `
      tls: tls
      username: alerts@example.test
      password: { env: SMTP_PW }
      from: lockkeeper@example.test
      to: [ops@example.test]
      ca_file: ` + srv.WriteCA(t) + `
`
	cfg, _, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Store.Path = filepath.Join(t.TempDir(), "state", "lockkeeper.db")
	env := map[string]string{"DB_PW": dbPassword, "TG_TOKEN": tgToken, "SMTP_PW": pw}
	ts := newTelegram(t)
	svc, err := New(cfg, Deps{
		Secrets:         secret.Resolver{Getenv: func(k string) (string, bool) { v, ok := env[k]; return v, ok && v != "" }},
		Log:             slog.New(slog.NewTextHandler(log, nil)),
		Redactor:        redact.New(),
		HTTP:            ts.Client(),
		NewCollector:    func(string) collector.Collector { return &fakeCollector{target: "db"} },
		RetrySleep:      func(context.Context, time.Duration) error { return nil },
		TelegramBaseURL: ts.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestAlertsTestSendsEmail(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.ImplicitTLS, User: "alerts@example.test", Password: smtpPasswordCanary})
	svc := emailService(t, srv, io.Discard, smtpPasswordCanary)

	res, err := svc.AlertsTest(context.Background(), "email")
	if err != nil || len(res) != 1 || res[0].Err != nil || res[0].Channel != "email" {
		t.Fatalf("results = %+v, err = %v", res, err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0].Data, "Subject: [WARNING] Test alert from Lockkeeper") {
		t.Fatalf("messages = %+v", msgs)
	}
	if strings.Contains(msgs[0].Data, smtpPasswordCanary) {
		t.Error("the password is in the message")
	}
}

func TestAlertsTestEmailFailureIsRedacted(t *testing.T) {
	// The server rejects the login and echoes what it received.
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.ImplicitTLS, User: "alerts@example.test", Password: "something-else", EchoAuthPayload: true})
	var logs strings.Builder
	svc := emailService(t, srv, &logs, smtpPasswordCanary)

	res, err := svc.AlertsTest(context.Background(), "email")
	if err != nil || len(res) != 1 || res[0].Err == nil {
		t.Fatalf("results = %+v, err = %v", res, err)
	}
	if strings.Contains(res[0].Err.Error(), smtpPasswordCanary) {
		t.Errorf("error leaks the password: %v", res[0].Err)
	}
	if strings.Contains(logs.String(), smtpPasswordCanary) {
		t.Error("log leaks the password")
	}
}

func TestEmailBadCAFileFailsFast(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.ImplicitTLS})
	svc := emailService(t, srv, io.Discard, smtpPasswordCanary)
	svc.cfg.Alerts.Channels.Email.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := svc.AlertsTest(context.Background(), "email"); err == nil || !strings.Contains(err.Error(), "ca_file") {
		t.Fatalf("err = %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.cfg.Alerts.Channels.Email.CAFile = bad
	if _, err := svc.AlertsTest(context.Background(), "email"); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifySecretsCoversTheEmailPassword(t *testing.T) {
	srv := fakesmtp.Start(t, fakesmtp.Options{Mode: fakesmtp.ImplicitTLS})
	svc := emailService(t, srv, io.Discard, "") // SMTP_PW unset
	res := svc.VerifySecrets(context.Background())
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "alerts.channels.email.password") {
		t.Errorf("problems = %v", res.Problems)
	}
}
