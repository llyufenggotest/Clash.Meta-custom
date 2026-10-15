package outboundgroup

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
)

func TestURLTestSelectsBlackstoneWithTCPHistory(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(port)
	p, err := adapter.ParseProxy(map[string]any{"name": "blackstone-live", "type": "Blackstone", "server": host, "port": pn, "password": "synthetic", "node-id": "never-fetch", "device_id": "synthetic-id", "device_name": "synthetic-name"})
	if err != nil {
		t.Fatal(err)
	}
	dead := namedProxy(t, "unmeasured-first")
	u := newURLTestGroup(t, "tcp-history-group", []C.Proxy{dead, p})
	if _, err := p.URLTest(context.Background(), u.testUrl, nil); err != nil {
		t.Fatal(err)
	}
	if u.noDelayData() {
		t.Fatal("TCP history invisible to automatic selection")
	}
	if got := u.Now(); got != p.Name() {
		t.Fatalf("selected %s want %s", got, p.Name())
	}
}
