package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	C "github.com/metacubex/mihomo/constant"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBlackstoneRealTLSCancellationAndVerification(t *testing.T) {
	// Real TLS listener and actual production transport, not a RoundTripper stub.
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	old := blackstoneAPIClient
	tr := xhttpAPITransport(nil)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	defer tr.CloseIdleConnections()
	// Trust the synthetic server cert, retaining hostname verification.
	tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	blackstoneAPIClient = func(_ C.Dialer) *http.Client {
		return &http.Client{Transport: tr, Timeout: time.Second, CheckRedirect: old(nil).CheckRedirect}
	}
	defer func() { blackstoneAPIClient = old }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := h.fetchDynamicConfig(ctx, "synthetic", "synthetic"); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("real HTTP transport cancellation lost")
	}
	// A wrong SNI must fail before sending credentials/HTTP bytes.
	tr.CloseIdleConnections()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = xhttpAPIHost
	_, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Fatal("hostname mismatch not verified")
	}
	select {
	case <-entered:
		t.Fatal("credentials reached wrong TLS identity")
	default:
	}
	if xhttpAPITransport(nil).Proxy != nil {
		t.Fatal("bootstrap unexpectedly inherits system HTTP proxy")
	}
}
