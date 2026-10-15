package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type probeRejectDialer struct{ calls atomic.Int32 }

var errProbeData = errors.New("synthetic data dialer")

func (d *probeRejectDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	return nil, errProbeData
}
func (*probeRejectDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	panic("unexpected packet dial")
}

func TestXHTTPURLTestConcurrentDataDialIsolation(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	acceptNotice := make(chan struct{}, 32)
	var accepted atomic.Int32
	go func() {
		defer close(done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			accepted.Add(1)
			acceptNotice <- struct{}{}
			c.Close()
		}
	}()
	defer func() { ln.Close(); <-done }()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	data := &probeRejectDialer{}
	h, err := NewXHttp(XHttpOption{BasicOption: BasicOption{DialerProxy: "must-stay", DialerForAPI: data}, Server: host})
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	h.isInit = true
	h.lastFetch = time.Now()
	h.bestCfg = xhttpRealConfig{Server: host, Port: port}
	wrapper := h
	const count = 32
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, e := wrapper.TCPProbe(context.Background()); e != nil {
				t.Error(e)
			}
		}()
		go func() {
			defer wg.Done()
			if _, e := h.DialContext(context.Background(), &C.Metadata{}); !errors.Is(e, errProbeData) {
				t.Errorf("data dial: %v", e)
			}
		}()
	}
	wg.Wait()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for i := 0; i < count; i++ {
		select {
		case <-acceptNotice:
		case <-timer.C:
			t.Fatal("direct accepts incomplete")
		}
	}
	ln.Close()
	<-done
	if data.calls.Load() != count || accepted.Load() != count || h.dialer != data || h.option.DialerProxy != "must-stay" || h.option.DialerForAPI != data {
		t.Fatalf("routing mutated: data=%d direct=%d", data.calls.Load(), accepted.Load())
	}
	// Dynamic-node ping race must still use the original API/data dialer.
	if _, e := h.pingRace(context.Background(), []xhttpRealConfig{h.bestCfg, h.bestCfg}); !errors.Is(e, errProbeData) {
		t.Fatalf("pingRace: %v", e)
	}
	if data.calls.Load() != count+2 {
		t.Fatal("pingRace bypassed data dialer")
	}
}

func TestXHTTPURLTestHonorsCanceledAndExpiredContext(t *testing.T) {
	for _, expired := range []bool{false, true} {
		h, err := NewXHttp(XHttpOption{Server: "127.0.0.1", Port: 1})
		if err != nil {
			t.Fatal(err)
		}
		var ctx context.Context
		var cancel context.CancelFunc
		want := context.Canceled
		if expired {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			want = context.DeadlineExceeded
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		defer cancel()
		if _, err := h.TCPProbe(ctx); !errors.Is(err, want) {
			t.Fatalf("expired=%v err=%v want=%v", expired, err, want)
		}
	}
}
