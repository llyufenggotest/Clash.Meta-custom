package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/tunnel"
)

// iOS Runner: after the extension takes over, the app core receives
// releaseConfig (executor.Shutdown + UpdateProxies(nil, nil)) but the process
// keeps running and still issues core HTTP requests (rule/geo/subscription).
// Previously inner kept routing those into a tunnel with no DIRECT adapter, which
// dereferenced a nil proxy and crashed the whole process.
func TestCoreHTTPAfterReleaseDialsDirectWithoutTunnel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(server.Close)

	initInnerTcp()
	tunnel.OnRunning()
	t.Cleanup(tunnel.OnSuspend)

	// Same order as core handleReleaseConfig.
	Shutdown()
	tunnel.UpdateProxies(nil, nil)
	t.Cleanup(func() { inner.New(nil) })

	if inner.GetTunnel() != nil {
		t.Fatal("released config still routes core HTTP through the inner tunnel")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, server.URL, http.MethodGet, nil, nil)
	if err != nil {
		t.Fatalf("core HTTP after release: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}
}

// Defence in depth: even if something routes into a tunnel whose proxies are
// gone, resolution must fail with an error instead of returning a nil adapter.
func TestResolveMetadataWithoutProxiesReturnsError(t *testing.T) {
	tunnel.UpdateProxies(nil, nil)
	initInnerTcp()
	tunnel.OnRunning()
	t.Cleanup(func() {
		tunnel.OnSuspend()
		inner.New(nil)
	})
	conn, err := inner.HandleTcp(inner.GetTunnel(), "127.0.0.1:9", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, readErr := conn.Read(buf)
	_ = conn.Close()
	if readErr == nil {
		t.Fatal("inner connection without proxies unexpectedly carried data")
	}
}
