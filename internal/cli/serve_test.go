package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServeRefusesNonLoopback(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8443", ":8443", "192.168.1.5:8443", "lockkeeper.example.net:8443"} {
		r := run(t, nil, nil, "serve", "--listen", addr)
		if r.code == 0 || !strings.Contains(r.err, "not a loopback") {
			t.Errorf("%s: want a refusal, got code %d stderr %q", addr, r.code, r.err)
		}
	}
}

func TestServeRejectsHalfATLSPair(t *testing.T) {
	r := run(t, nil, nil, "serve", "--tls-cert", "cert.pem")
	if r.code == 0 || !strings.Contains(r.err, "together") {
		t.Fatalf("want an error about the certificate/key pair, got %d %q", r.code, r.err)
	}
}

func TestServeServesHealthAndStopsOnSignal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // the CLI binds the address itself; we only needed a free port

	var stderr bytes.Buffer
	env := Env{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: &stderr, Getenv: func(string) (string, bool) { return "", false }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- Execute(ctx, env, []string{"serve", "--listen", addr}) }()

	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + addr + "/api/v1/health")
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("server never answered: %v (stderr %s)", err, stderr.String())
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "ok") {
		t.Fatalf("health: %d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("the served response must carry the CSP")
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d after shutdown, stderr %s", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop")
	}
	if !strings.Contains(stderr.String(), fmt.Sprintf("http://%s/", addr)) || !strings.Contains(stderr.String(), "demo data") {
		t.Fatalf("the banner must say where it listens and that the data is demo data: %q", stderr.String())
	}
}
