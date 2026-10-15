package outbound

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestBlackstonePingDeadlinePreservesCallerCause(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	h.dialer = &blackstoneRaceDialer{done: make(chan struct{})}
	envelope := fixtureBlackstoneRoutedEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: loser, port: 1, password: 'synthetic:00'}\n - {name: synthetic-2, type: xhttp, server: loser, port: 2, password: 'synthetic:00'}\n")
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := h.DialContext(ctx, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("node selection lost caller deadline cause")
	}
}
