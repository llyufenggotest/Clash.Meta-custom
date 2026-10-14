package provider

import (
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

func TestProxyHTTPFetcherCloseRevokesSubscriptionAndETag(t *testing.T) {
	dir := t.TempDir()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(dir)
	defer C.SetHomeDir(oldHome)
	originalETag := resource.ETag()
	resource.SetETag(true)
	defer resource.SetETag(originalETag)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=1; download=2")
		w.Header().Set("ETag", "late")
		_, _ = w.Write([]byte("proxies"))
	}))
	defer server.Close()
	vehicle := resource.NewHTTPVehicle(server.URL, filepath.Join(dir, "raw"), "", nil, 10*time.Second, 0)
	p, err := NewProxySetProvider("http-owned", 0, nil, func([]byte) ([]C.Proxy, error) { return []C.Proxy{nil}, nil }, vehicle, NewHealthCheck(nil, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	cache := cachefile.Cache()
	if cache.DB != nil && cache.DB.Path() == C.Path.Cache() {
		defer cache.Close()
	}
	p.mutex.Lock()
	done := make(chan struct{})
	go func() { _, _, _ = p.Fetcher.Update(); close(done) }()
	// Header cache publication precedes the actual production subscription
	// callback waiting for the provider lock. This is a real loopback HTTP Read.
	deadline := time.After(10 * time.Second)
	for cachefile.Cache().GetSubscriptionInfo("http-owned") == "" {
		select {
		case <-deadline:
			p.mutex.Unlock()
			t.Fatal("HTTP header hook not reached")
		default:
		}
	}
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		p.mutex.Unlock()
		t.Fatal("Close joined HTTP header callback")
	}
	p.mutex.Unlock()
	<-done
	if p.subscriptionSnapshot() != nil || p.Count() != 0 || !p.UpdatedAt().IsZero() {
		t.Fatal("late subscription/proxy/metadata commit")
	}
	if value := cachefile.Cache().GetETagWithHash(server.URL); value.Hash.Equal(utils.MakeHash([]byte("proxies"))) || value.ETag == "late" {
		t.Fatal("late ETag publication")
	}
}

func TestProxyFetcherCloseRevokesBlockedProductionPublication(t *testing.T) {
	entered := make(chan struct{})
	hc := NewHealthCheck(nil, "", 0, 0, false, nil)
	p, err := NewProxySetProvider("owned", 0, nil, func([]byte) ([]C.Proxy, error) { close(entered); return []C.Proxy{nil}, nil }, resource.NewFileVehicle(filepath.Join(t.TempDir(), "rules")), hc)
	if err != nil {
		t.Fatal(err)
	}
	p.mutex.Lock()
	done := make(chan struct{})
	go func() { _, _, _ = p.Fetcher.SideUpdate([]byte("proxies")); close(done) }()
	<-entered
	deadline := time.After(10 * time.Second)
	for p.UpdatedAt().IsZero() {
		select {
		case <-deadline:
			p.mutex.Unlock()
			t.Fatal("update did not reach callback")
		default:
		}
	}
	// The actual production callback blocks on baseProvider.mutex, not a
	// replacement callback. Close must not join it or publish after revocation.
	closed := make(chan struct{})
	go func() { _ = p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		p.mutex.Unlock()
		t.Fatal("Close joined production callback")
	}
	p.mutex.Unlock()
	<-done
	if p.Count() != 0 || p.Version() != 0 || len(hc.proxies) != 0 {
		t.Fatal("revoked production callback published proxies/version/healthcheck")
	}
}
