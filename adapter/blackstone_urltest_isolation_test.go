package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
)

func TestNonBlackstoneURLTestRetainsFrontProxy(t *testing.T) {
	front := &probeFront{Base: outbound.NewBase(outbound.BaseOption{Name: "front-select"})}
	p, err := ParseProxy(map[string]any{"name": "unrelated-socks", "type": "socks5", "server": "127.0.0.1", "port": 1, "dialer-proxy": "front-select"}, WithTunnelForAPI(probeTunnel{front: NewProxy(front)}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = p.URLTest(ctx, "http://127.0.0.1:1", nil); !errors.Is(err, errProbeFront) {
		t.Fatalf("unrelated URLTest err=%v", err)
	}
	if front.calls.Load() == 0 {
		t.Fatal("unrelated URLTest unexpectedly bypassed front proxy")
	}
}
