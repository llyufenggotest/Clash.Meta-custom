package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

func TestIndependentHTTPDeadlineRejectsLateSubscriptionPublication(t *testing.T) {
	dir := t.TempDir()
	old := C.Path.HomeDir()
	C.SetHomeDir(dir)
	defer C.SetHomeDir(old)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=99; download=88")
		_, _ = w.Write([]byte("proxies: []\n"))
	}))
	defer server.Close()
	hc := NewHealthCheck(nil, "", 0, 0, false, nil)
	v := resource.NewHTTPVehicle(server.URL, filepath.Join(dir, "cache"), "", nil, 2*time.Second, 0)
	p, err := NewProxySetProvider("deadline-late", 0, nil, func([]byte) ([]C.Proxy, error) { return []C.Proxy{nil}, nil }, v, hc)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cache := cachefile.Cache()
	if cache.DB == nil || cache.DB.Path() == "" {
		t.Fatal("process-owned metadata cache is not open")
	}
	// A prior -count iteration's sidefile must not satisfy this HTTP barrier.
	cache.SetSubscriptionInfo("deadline-late", "")
	p.mutex.Lock()
	locked := true
	defer func() {
		if locked {
			p.mutex.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- p.Update() }()
	deadline := time.Now().Add(3 * time.Second)
	for cache.GetSubscriptionInfo("deadline-late") != "upload=99; download=88" {
		if time.Now().After(deadline) {
			t.Fatal("HTTP metadata callback not reached")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(2500 * time.Millisecond)
	p.mutex.Unlock()
	locked = false
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Update err=%v want deadline", err)
	}
	if info := p.subscriptionSnapshot(); info != nil {
		t.Fatalf("request canceled before provider lock acquired, but published subscription=%+v", info)
	}
	if p.Count() != 0 || p.Version() != 0 || !p.UpdatedAt().IsZero() || len(hc.proxies) != 0 {
		t.Fatal("expired HTTP request published proxies/version/updatedAt/healthcheck")
	}
	if got := cache.GetSubscriptionInfo("deadline-late"); got != "upload=99; download=88" {
		t.Fatalf("timely HTTP header cache=%q", got)
	}
}

func TestIndependentHTTPDeadlinePreservesTimelySubscriptionPublication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("subscription-userinfo", "upload=99; download=88")
		_, _ = w.Write([]byte("proxies: []\n"))
	}))
	defer server.Close()
	v := resource.NewHTTPVehicle(server.URL, filepath.Join(t.TempDir(), "cache"), "", nil, 2*time.Second, 0)
	p, err := NewProxySetProvider("deadline-timely", 0, nil, func([]byte) ([]C.Proxy, error) { return []C.Proxy{nil}, nil }, v, NewHealthCheck(nil, "", 0, 0, false, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Update(); err != nil {
		t.Fatal(err)
	}
	if info := p.subscriptionSnapshot(); info == nil || info.Upload != 99 || info.Download != 88 {
		t.Fatalf("timely subscription=%+v", info)
	}
	if p.Count() != 1 || p.Version() != 1 || p.UpdatedAt().IsZero() {
		t.Fatal("timely HTTP update did not publish proxies/version/updatedAt")
	}
	if got := cachefile.Cache().GetSubscriptionInfo("deadline-timely"); got != "upload=99; download=88" {
		t.Fatalf("timely HTTP header cache=%q", got)
	}
}
