package outbound

import (
	"context"
	C "github.com/metacubex/mihomo/constant"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type blackstoneClosingTransport struct{ closed atomic.Bool }

func (tr *blackstoneClosingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":401}`))}, nil
}
func (tr *blackstoneClosingTransport) CloseIdleConnections() { tr.closed.Store(true) }
func TestBlackstoneOneShotTransportReleasesIdleConnections(t *testing.T) {
	old := blackstoneAPIClient
	defer func() { blackstoneAPIClient = old }()
	tr := &blackstoneClosingTransport{}
	blackstoneAPIClient = func(C.Dialer) *http.Client { return &http.Client{Transport: tr} }
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
	if !tr.closed.Load() {
		t.Fatal("per-fetch transport retains idle connection goroutines")
	}
}
