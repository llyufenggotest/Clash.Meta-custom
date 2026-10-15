package executor

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
)

// Uses only baseline APIs: a second admitted HTTP request releases the first.
// The timeout releases a sequential baseline so it reaches the peak assertion;
// it is not a startup-performance threshold.
func TestPreflightBaselineRemoteReadsOverlap(t *testing.T) {
	var active, peak, hits atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	timer := time.AfterFunc(2*time.Second, func() { once.Do(func() { close(release) }) })
	defer timer.Stop()
	defer once.Do(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		if n > 1 {
			once.Do(func() { close(release) })
		}
		<-release
		_, _ = io.WriteString(w, "DOMAIN-SUFFIX,"+filepath.Base(r.URL.Path)+".example\n")
	}))
	defer server.Close()
	providers := make(map[string]P.RuleProvider)
	dir := t.TempDir()
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("rule%02d", i)
		v := resource.NewHTTPVehicle(server.URL+"/"+name, filepath.Join(dir, name), "", nil, 5*time.Second, 0)
		providers[name] = RP.NewRuleSetProvider(name, P.Classical, P.TextRule, 0, v, nil, nil, R.ParseRule)
	}
	defer closeRuleProviders(providers)
	if err := preflightRuleProviders(providers, false); err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got <= 1 {
		t.Fatalf("remote reads stayed sequential: peak=%d, want >1", got)
	}
	if got := peak.Load(); got > 6 {
		t.Fatalf("remote read window exceeded: peak=%d, want <=6", got)
	}
	if hits.Load() != 12 {
		t.Fatalf("hits=%d, want 12", hits.Load())
	}
	for name, p := range providers {
		if p.Count() != 1 {
			t.Fatalf("%s count=%d", name, p.Count())
		}
	}
}
