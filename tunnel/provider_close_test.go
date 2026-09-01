package tunnel

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/common/utils"
)

// fakeProvider is the smallest ProxyProvider that also reports whether it was
// closed. Switching subscriptions used to drop the old providers on the floor,
// leaving their health-check goroutines probing dead nodes forever and pinning
// every proxy they referenced -- fatal for the iOS jetsam budget.
type fakeProvider struct {
	name   string
	closed int
}

func (f *fakeProvider) Name() string                { return f.name }
func (f *fakeProvider) VehicleType() P.VehicleType  { return P.File }
func (f *fakeProvider) Type() P.ProviderType        { return P.Proxy }
func (f *fakeProvider) Initial() error              { return nil }
func (f *fakeProvider) Update() error               { return nil }
func (f *fakeProvider) Proxies() []C.Proxy          { return nil }
func (f *fakeProvider) Count() int                  { return 0 }
func (f *fakeProvider) Touch()                      {}
func (f *fakeProvider) HealthCheck()                {}
func (f *fakeProvider) Version() uint32             { return 0 }
func (f *fakeProvider) HealthCheckURL() string      { return "" }
func (f *fakeProvider) RegisterHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
}
func (f *fakeProvider) Close() error { f.closed++; return nil }

// uncloseableProvider has no Close: a provider type that does not own a
// goroutine must keep working, not panic.
type uncloseableProvider struct {
	fakeProvider
}

func (u *uncloseableProvider) Close() { panic("must not be called via io.Closer") }

func TestStaleProvidersAreClosedOnSwitch(t *testing.T) {
	oldA := &fakeProvider{name: "sub-a-1"}
	oldB := &fakeProvider{name: "sub-a-2"}
	newA := &fakeProvider{name: "sub-b-1"}

	stale := staleProviders(
		map[string]P.ProxyProvider{"sub-a-1": oldA, "sub-a-2": oldB},
		map[string]P.ProxyProvider{"sub-b-1": newA},
	)
	if len(stale) != 2 {
		t.Fatalf("expected both previous providers to be stale, got %d", len(stale))
	}
	closeProviders(stale)

	if oldA.closed != 1 || oldB.closed != 1 {
		t.Fatalf("stale providers must be closed exactly once, got a=%d b=%d", oldA.closed, oldB.closed)
	}
	if newA.closed != 0 {
		t.Fatalf("the incoming provider must never be closed, got %d", newA.closed)
	}
}

// A reload of the same subscription builds fresh provider objects under the
// same names. Comparing by name would leak the old objects, so identity has to
// be by pointer.
func TestSameNameRebuildStillClosesTheOldObject(t *testing.T) {
	before := &fakeProvider{name: "provider"}
	after := &fakeProvider{name: "provider"}

	stale := staleProviders(
		map[string]P.ProxyProvider{"provider": before},
		map[string]P.ProxyProvider{"provider": after},
	)
	closeProviders(stale)

	if before.closed != 1 {
		t.Fatalf("rebuilt provider under the same name must still be closed, got %d", before.closed)
	}
	if after.closed != 0 {
		t.Fatalf("the replacement must stay open, got %d", after.closed)
	}
}

// A provider carried over into the new config must not be closed: its
// health-check goroutine is still the live one.
func TestRetainedProviderIsNotClosed(t *testing.T) {
	shared := &fakeProvider{name: "shared"}
	dropped := &fakeProvider{name: "dropped"}

	stale := staleProviders(
		map[string]P.ProxyProvider{"shared": shared, "dropped": dropped},
		map[string]P.ProxyProvider{"shared": shared},
	)
	closeProviders(stale)

	if shared.closed != 0 {
		t.Fatalf("retained provider must stay open, got %d", shared.closed)
	}
	if dropped.closed != 1 {
		t.Fatalf("dropped provider must be closed, got %d", dropped.closed)
	}
}

func TestFirstLoadHasNothingToClose(t *testing.T) {
	if stale := staleProviders(nil, map[string]P.ProxyProvider{"a": &fakeProvider{name: "a"}}); len(stale) != 0 {
		t.Fatalf("a first load has no previous providers, got %d", len(stale))
	}
}

func TestNilProviderEntryIsSkipped(t *testing.T) {
	stale := staleProviders(
		map[string]P.ProxyProvider{"broken": nil},
		map[string]P.ProxyProvider{},
	)
	if len(stale) != 0 {
		t.Fatalf("a nil entry must not be reported as stale, got %d", len(stale))
	}
	closeProviders(stale) // must not panic
}

// The helper tests above still pass if UpdateProxies forgets to call it, so this
// one drives the real entry point: it is the only test that fails when the
// wiring inside UpdateProxies is removed.
func TestUpdateProxiesClosesTheReplacedProviders(t *testing.T) {
	previousProxies, previousProviders := proxies, providers
	t.Cleanup(func() {
		configMux.Lock()
		proxies, providers = previousProxies, previousProviders
		configMux.Unlock()
	})

	oldProvider := &fakeProvider{name: "subscription-a"}
	newProvider := &fakeProvider{name: "subscription-b"}

	UpdateProxies(map[string]C.Proxy{}, map[string]P.ProxyProvider{"subscription-a": oldProvider})
	if oldProvider.closed != 0 {
		t.Fatalf("installing a provider must not close it, got %d", oldProvider.closed)
	}

	UpdateProxies(map[string]C.Proxy{}, map[string]P.ProxyProvider{"subscription-b": newProvider})
	if oldProvider.closed != 1 {
		t.Fatalf("switching subscriptions must close the replaced provider exactly once, got %d", oldProvider.closed)
	}
	if newProvider.closed != 0 {
		t.Fatalf("the newly installed provider must stay open, got %d", newProvider.closed)
	}
	if len(providers) != 1 || providers["subscription-b"] != newProvider {
		t.Fatalf("tunnel must end up holding only the new provider, got %#v", providers)
	}
}
