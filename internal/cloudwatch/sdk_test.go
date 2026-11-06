package cloudwatch

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
)

// These tests drive the real SDK client, but only ever against a server on
// 127.0.0.1: the HTTP client below refuses to dial anything else, so a bug here
// cannot reach AWS. They check how Lockkeeper configures the SDK (credential
// chain, signing, retries, error text), not what AWS answers.

const (
	testAccessKey = "AKIAFAKEFAKEFAKE0000"
	testSecretKey = "CANARY-aws-secret-key-0f1e2d3c"
)

type recorded struct {
	auth, path, protocol, host string
	body                       string
}

type fakeAWS struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []recorded
}

// cborError encodes the error document the SDK's rpc-v2-cbor protocol expects:
// a definite-length map with two short text strings.
func cborError(code, message string) string {
	text := func(s string) string {
		if len(s) >= 24 {
			panic("test helper handles short strings only")
		}
		return string(rune(0x60+len(s))) + s
	}
	return "\xa2" + text("__type") + text(code) + text("message") + text(message)
}

func newFakeAWS(t *testing.T, status int, body string) *fakeAWS {
	t.Helper()
	f := &fakeAWS{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{
			auth: r.Header.Get("Authorization"), path: r.URL.Path,
			protocol: r.Header.Get("Smithy-Protocol"), host: r.Host, body: string(b),
		})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Smithy-Protocol", "rpc-v2-cbor")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAWS) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

// loopbackOnly is an HTTP client that cannot dial a non-loopback address and
// ignores proxy settings.
func loopbackOnly() *http.Client {
	var d net.Dialer
	return &http.Client{Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("test guard: refusing to dial %q", host)
			}
			return d.DialContext(ctx, network, addr)
		},
	}}
}

// hermeticAWSEnv gives the SDK known credentials and hides any real AWS setup.
func hermeticAWSEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", testAccessKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", testSecretKey)
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ENDPOINT_URL", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
}

func lazyFor(srv *fakeAWS, region string) *lazyClient {
	return &lazyClient{
		region:     region,
		loadOpts:   []func(*config.LoadOptions) error{config.WithHTTPClient(loopbackOnly())},
		clientOpts: []func(*cw.Options){func(o *cw.Options) { o.BaseEndpoint = aws.String(srv.URL) }},
	}
}

func TestSDKUsesTheStandardCredentialChainAndNeverLeaksTheSecret(t *testing.T) {
	hermeticAWSEnv(t)
	srv := newFakeAWS(t, http.StatusForbidden, cborError("AccessDenied", "not authorized"))
	now := t0
	c := New("rds-main", "example-db", lazyFor(srv, "eu-west-1"), Options{Now: func() time.Time { return now }})

	samples, complete, err := c.Collect(context.Background())
	if len(samples) != 0 || complete || err == nil {
		t.Fatalf("samples=%v complete=%v err=%v", samples, complete, err)
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("error should name the AWS error code: %v", err)
	}
	for _, leak := range []string{testSecretKey, testAccessKey} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error contains a credential: %v", err)
		}
	}

	reqs := srv.requests()
	if len(reqs) == 0 {
		t.Fatal("no request reached the fake")
	}
	r := reqs[0]
	if !strings.Contains(r.auth, "Credential="+testAccessKey+"/") || !strings.Contains(r.auth, "/eu-west-1/monitoring/aws4_request") {
		t.Errorf("request is not signed with the environment credentials for monitoring/eu-west-1: %q", r.auth)
	}
	if strings.Contains(r.auth, testSecretKey) || strings.Contains(r.body, testSecretKey) {
		t.Error("the secret key was sent in clear")
	}
	if !strings.HasSuffix(r.path, "/operation/GetMetricData") {
		t.Errorf("path = %q", r.path)
	}
	if !strings.Contains(r.body, "FreeStorageSpace") || !strings.Contains(r.body, "example-db") || !strings.Contains(r.body, "DBInstanceIdentifier") {
		t.Errorf("request body does not carry the query (protocol %q)", r.protocol)
	}
}

func TestSDKRetriesAreSmallAndBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("takes a few seconds of backoff")
	}
	hermeticAWSEnv(t)
	srv := newFakeAWS(t, http.StatusInternalServerError, cborError("InternalFailure", "boom"))
	l := lazyFor(srv, "eu-west-1")
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := l.GetMetricData(ctx, New("t", "i", nil, Options{Now: func() time.Time { return t0 }}).request(t0))
	if err == nil {
		t.Fatal("expected an error")
	}
	if n := len(srv.requests()); n != 3 {
		t.Errorf("attempts = %d, want 3", n)
	}
	if d := time.Since(start); d > 12*time.Second {
		t.Errorf("retries took %v", d)
	}
}

func TestSDKConfigErrorsDoNotEchoFileContents(t *testing.T) {
	hermeticAWSEnv(t)
	bad := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(bad, []byte("[profile broken\naws_secret_access_key = "+testSecretKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", bad)
	l := &lazyClient{region: "eu-west-1"}
	_, err := l.GetMetricData(context.Background(), &cw.GetMetricDataInput{})
	if err == nil {
		t.Fatal("expected a configuration error")
	}
	if strings.Contains(err.Error(), testSecretKey) || strings.Contains(err.Error(), bad) {
		t.Errorf("error echoes configuration: %v", err)
	}
}

func TestNewSDKDoesNothingUntilUsed(t *testing.T) {
	// No environment, no network: constructing must not read config or call AWS.
	l := NewSDK("eu-west-1").(*lazyClient)
	if l.client != nil {
		t.Error("client built eagerly")
	}
}
