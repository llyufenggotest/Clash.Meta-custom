package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/probelimit"
	"github.com/metacubex/mihomo/common/utils"
)

func TestBlackstoneURLTestHistoryConcurrentAndFailure(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	defer func() { ln.Close(); <-done }()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(port)
	p, err := ParseProxy(map[string]any{"name": "history", "type": "Blackstone", "server": host, "port": pn, "password": "synthetic", "node-id": "never-fetch", "device_id": "synthetic-id", "device_name": "synthetic-name"})
	if err != nil {
		t.Fatal(err)
	}
	const url = "not-an-http-url"
	oldHook := UrlTestHook
	var hooks atomic.Int32
	UrlTestHook = func(u, name string, delay uint16) {
		if u != url || name != "history" {
			t.Errorf("hook %q/%q", u, name)
		}
		hooks.Add(1)
	}
	t.Cleanup(func() { UrlTestHook = oldHook })
	// An impossible HTTP status must not affect a pure TCP measurement.
	statuses := utils.IntRanges[uint16]{utils.NewRange[uint16](599, 599)}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if d, e := p.URLTest(ctx, url, statuses); e != nil || d == 0 || d == 65535 {
				t.Errorf("probe delay=%d error=%v", d, e)
			}
		}()
	}
	wg.Wait()
	extra := p.ExtraDelayHistories()[url]
	if len(p.DelayHistory()) != 10 || len(extra.History) != 10 || !extra.Alive || !p.AliveForTestUrl(url) || p.LastDelayForTestUrl(url) == 65535 || hooks.Load() != 32 {
		t.Fatalf("history=%v extra=%v hooks=%d", p.DelayHistory(), extra, hooks.Load())
	}
	ln.Close()
	<-done
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := p.URLTest(ctx, url, nil); err == nil {
		t.Fatal("closed listener succeeded")
	}
	extra = p.ExtraDelayHistories()[url]
	if extra.Alive || p.AliveForTestUrl(url) || p.LastDelayForTestUrl(url) != 65535 || extra.History[len(extra.History)-1].Delay != 0 || hooks.Load() != 33 {
		t.Fatalf("failure state=%v hooks=%d", extra, hooks.Load())
	}
	raw, err := p.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Alive bool `json:"alive"`
	}
	if err := json.Unmarshal(raw, &state); err != nil || state.Alive {
		t.Fatalf("serialized alive=%v err=%v", state.Alive, err)
	}
}

type cancelTCPProbe struct {
	*outbound.Base
	started chan struct{}
}

func (p *cancelTCPProbe) TCPProbe(ctx context.Context) (uint16, error) {
	close(p.started)
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestTCPProbeCancellationUsesCommonStateContract(t *testing.T) {
	a := &cancelTCPProbe{Base: outbound.NewBase(outbound.BaseOption{Name: "cancel"}), started: make(chan struct{})}
	p := NewProxy(a)
	oldHook := UrlTestHook
	var hooks atomic.Int32
	UrlTestHook = func(string, string, uint16) { hooks.Add(1) }
	t.Cleanup(func() { UrlTestHook = oldHook })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := p.URLTest(ctx, "cancel", nil); done <- err }()
	<-a.started
	if probelimit.Enabled {
		probelimit.Default.CancelAll()
	} else {
		cancel()
	}
	defer cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if probelimit.Enabled {
		if len(p.DelayHistory()) != 0 || len(p.ExtraDelayHistories()) != 0 || !p.AliveForTestUrl("cancel") || hooks.Load() != 0 {
			t.Fatal("NE cancellation marked node dead")
		}
	} else {
		if len(p.DelayHistory()) != 1 || p.AliveForTestUrl("cancel") || hooks.Load() != 1 {
			t.Fatal("default cancellation contract changed")
		}
	}
}
