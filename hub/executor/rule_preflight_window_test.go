package executor

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

type windowProbe struct {
	P.RuleProvider
	started    *atomic.Int32
	six, seven chan struct{}
	first      bool
}

func (p *windowProbe) FetchInitial() (resource.InitialFetch, error) {
	n := p.started.Add(1)
	if n == 6 {
		close(p.six)
	}
	if n == 7 {
		close(p.seven)
	}
	return p.RuleProvider.(initialFetcher).FetchInitial()
}
func (p *windowProbe) InitialFromFetch(f resource.InitialFetch) error {
	if p.first {
		select {
		case <-p.six:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("window never filled")
		}
		select {
		case <-p.seven:
			return fmt.Errorf("seventh raw read admitted before first parse released its token")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return p.RuleProvider.(initialFetcher).InitialFromFetch(f)
}
func TestPreflightWindowIncludesCurrentlyParsingBuffer(t *testing.T) {
	s := newSlowRuleServer(t, 0)
	inner := newRemoteRuleProviders(t, s.URL, 12)
	var started atomic.Int32
	six, seven := make(chan struct{}), make(chan struct{})
	ps := make(map[string]P.RuleProvider)
	for n, p := range inner {
		ps[n] = &windowProbe{RuleProvider: p, started: &started, six: six, seven: seven, first: n == "rp00"}
	}
	if err := preflightRuleProviders(ps, false); err != nil {
		t.Fatal(err)
	}
}
