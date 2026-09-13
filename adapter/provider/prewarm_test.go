package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareProxyProviderDownloadsParsesAndStages(t *testing.T) {
	body := []byte("proxies:\n  - name: staged\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()

	target := filepath.Join(t.TempDir(), "provider.yaml")
	result, err := PrepareProxyProvider(context.Background(), "remote", map[string]any{
		"type": "http", "url": server.URL,
		"health-check": map[string]any{"enable": true, "url": "https://example.invalid", "interval": 1},
	}, target, filepath.Dir(target), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 1 || result.Digest == "" || result.Path != target {
		t.Fatalf("result=%+v", result)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("staged bytes changed: %q", got)
	}
	sum := sha256.Sum256(body)
	if result.Digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest=%q", result.Digest)
	}
}

func TestPrepareProxyProviderRejectsInvalidContentWithoutPublishing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxies:\n  - name: broken\n    type: not-a-proxy\n"))
	}))
	defer server.Close()

	target := filepath.Join(t.TempDir(), "provider.yaml")
	if _, err := PrepareProxyProvider(context.Background(), "broken", map[string]any{
		"type": "http", "url": server.URL,
	}, target, filepath.Dir(target), time.Second); err == nil {
		t.Fatal("invalid proxy provider was accepted")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("invalid provider was published: %v", err)
	}
}

func TestPrepareProxyProviderHonorsCancellationAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	for name, ctx := range map[string]context.Context{
		"cancel":  func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }(),
		"timeout": context.Background(),
	} {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "provider.yaml")
			_, err := PrepareProxyProvider(ctx, name, map[string]any{"type": "http", "url": server.URL}, target, filepath.Dir(target), 20*time.Millisecond)
			if err == nil || (!strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "deadline")) {
				t.Fatalf("err=%v", err)
			}
			if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
				t.Fatalf("timed out provider was published: %v", statErr)
			}
		})
	}
}
