package config

import (
	"strings"
	"testing"
)

// emailYAML returns validYAML plus an email channel with the given body.
func emailYAML(body string) string {
	return strings.Replace(validYAML, "    slack:\n", "    email:\n"+body+"    slack:\n", 1)
}

const goodEmail = `      host: smtp.example.com
      username: alerts@example.com
      password: { env: LK_SMTP_PASSWORD }
      from: Lockkeeper <lockkeeper@example.com>
      to: [ops@example.com, oncall@example.com]
`

func TestEmailDefaultsAndRouting(t *testing.T) {
	cfg, warnings, err := Parse([]byte(strings.Replace(emailYAML(goodEmail), "to: [telegram, slack]", "to: [email]", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}
	e := cfg.Alerts.Channels.Email
	if e.TLS != "starttls" || e.Port != 587 {
		t.Errorf("defaults = %s/%d", e.TLS, e.Port)
	}
	if got := strings.Join(cfg.ChannelNames(), ","); got != "telegram,slack,email" {
		t.Errorf("channels = %s", got)
	}

	cfg, _, err = Parse([]byte(emailYAML(goodEmail + "      tls: tls\n")))
	if err != nil {
		t.Fatal(err)
	}
	if e := cfg.Alerts.Channels.Email; e.Port != 465 {
		t.Errorf("implicit TLS port = %d", e.Port)
	}
}

func TestEmailValidationErrors(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"no host", strings.Replace(goodEmail, "host: smtp.example.com", "host: \"\"", 1), "email.host: required"},
		{"url as host", strings.Replace(goodEmail, "smtp.example.com", "smtp://x@smtp.example.com", 1), "host name or IP"},
		{"bad tls", goodEmail + "      tls: ssl\n", "tls: must be one of"},
		{"plaintext remote", goodEmail + "      tls: none\n", "refused for remote host"},
		{"plaintext remote insecure with credentials", goodEmail + "      tls: none\n      allow_insecure: true\n", "never sent over an unencrypted"},
		{"username without password", "      host: smtp.example.com\n      username: u\n      from: a@example.com\n      to: [b@example.com]\n", "password: required when username"},
		{"password without username", "      host: smtp.example.com\n      password: { env: X }\n      from: a@example.com\n      to: [b@example.com]\n", "username: required when password"},
		{"inline password", strings.Replace(goodEmail, "{ env: LK_SMTP_PASSWORD }", "hunter2", 1), "inline secrets are not allowed"},
		{"bad from", strings.Replace(goodEmail, "Lockkeeper <lockkeeper@example.com>", "not-an-address", 1), "email.from"},
		{"no recipients", strings.Replace(goodEmail, "to: [ops@example.com, oncall@example.com]", "to: []", 1), "at least one recipient"},
		{"bad recipient", strings.Replace(goodEmail, "oncall@example.com", "oncall", 1), "email.to[1]"},
		{"CRLF recipient", strings.Replace(goodEmail, "[ops@example.com, oncall@example.com]", "[\"ops@example.com\\r\\nBcc: x@example.com\"]", 1), "control characters"},
		{"bad port", goodEmail + "      port: 70000\n", "port: must be 1-65535"},
	}
	for _, c := range cases {
		_, _, err := Parse([]byte(emailYAML(c.body)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error leaks the inline value", c.name)
		}
	}
}

func TestEmailPlaintextRules(t *testing.T) {
	// Loopback relay without TLS is fine, even with credentials.
	loop := strings.Replace(goodEmail, "smtp.example.com", "127.0.0.1", 1) + "      tls: none\n"
	if _, w, err := Parse([]byte(emailYAML(loop))); err != nil || len(w) != 0 {
		t.Errorf("loopback none: err=%v warnings=%v", err, w)
	}
	// A remote unauthenticated relay is allowed only with the explicit opt-in, and warns.
	remote := "      host: relay.example.com\n      tls: none\n      allow_insecure: true\n      from: a@example.com\n      to: [b@example.com]\n"
	_, w, err := Parse([]byte(emailYAML(remote)))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range w {
		found = found || strings.Contains(x, "sends alert text unencrypted")
	}
	if !found {
		t.Errorf("expected a warning, got %v", w)
	}
}
