package adapter

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

var errProbeFront = errors.New("synthetic front proxy reached")

type probeFront struct {
	*outbound.Base
	calls atomic.Int32
}

func (p *probeFront) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	p.calls.Add(1)
	return nil, errProbeFront
}

type probeTunnel struct {
	C.Tunnel
	front C.Proxy
}

func (t probeTunnel) Proxies() map[string]C.Proxy { return map[string]C.Proxy{"front-select": t.front} }

func TestBlackstoneURLTestBypassesFrontProxy(t *testing.T) {
	for _, typ := range []string{"Blackstone", "xhttp"} {
		for _, withFront := range []bool{false, true} {
			t.Run(typ+"/front="+strconv.FormatBool(withFront), func(t *testing.T) {
				ln, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				var accepted atomic.Int32
				done := make(chan struct{})
				acceptNotice := make(chan struct{}, 1)
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
				front := &probeFront{Base: outbound.NewBase(outbound.BaseOption{Name: "front-select"})}
				host, port, _ := net.SplitHostPort(ln.Addr().String())
				pn, _ := strconv.Atoi(port)
				mapping := map[string]any{"name": "probe", "type": typ, "server": host, "port": pn, "password": "synthetic", "node-id": "never-fetch", "device_id": "synthetic", "device_name": "synthetic"}
				if withFront {
					mapping["dialer-proxy"] = "front-select"
				}
				p, err := ParseProxy(mapping, WithTunnelForAPI(probeTunnel{front: NewProxy(front)}))
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_, err = p.URLTest(ctx, "https://must-not-request.invalid", nil)
				if err == nil {
					select {
					case <-acceptNotice:
					case <-ctx.Done():
						t.Fatal("direct accept not observed")
					}
				}
				ln.Close()
				<-done
				if err != nil || front.calls.Load() != 0 || accepted.Load() != 1 {
					t.Fatalf("URLTest err=%v front_calls=%d direct_accepts=%d; want nil/0/1", err, front.calls.Load(), accepted.Load())
				}
				// Audit only: preserve the existing wrapper's missing history behavior.
				if len(p.DelayHistory()) != 0 || len(p.ExtraDelayHistories()) != 0 || p.LastDelayForTestUrl("https://must-not-request.invalid") != 65535 {
					t.Fatal("history behavior unexpectedly changed")
				}
			})
		}
	}
}
