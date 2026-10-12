package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	C "github.com/metacubex/mihomo/constant"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestBlackstoneHTTPPolicy(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Host != xhttpAPIHost || r.URL.Path != "/api/v3/proxy/config" || r.Header.Get("x-version") != "540" {
			t.Error("request producer mismatch")
		}
		body, _ := io.ReadAll(r.Body)
		var outer map[string]string
		if json.Unmarshal(body, &outer) != nil {
			t.Error("bad request envelope")
		}
		raw, _ := base64.StdEncoding.DecodeString(outer["data"])
		for i := range raw {
			raw[i] ^= xhttpPubKey[i%len(xhttpPubKey)]
		}
		var request map[string]any
		if json.Unmarshal(raw, &request) != nil || request["id"] != "synthetic-node" || request["strategy"] != "smart" || request["energy"] != false || len(request) != 4 {
			t.Error("request body changed")
		}
		if _, ok := request["fastest_ping"].(map[string]any); !ok {
			t.Error("fastest_ping changed")
		}
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(302)
	}))
	defer s.Close()
	transport := xhttpAPITransport(nil)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
	transport.TLSClientConfig = nil
	// Exercise the actual API method via an HTTP fixture client; URL is asserted before forwarding.
	old := blackstoneAPIClient
	blackstoneAPIClient = func(d C.Dialer) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme != "https" || r.URL.Host != xhttpAPIHost {
				t.Error("API does not use canonical TLS hostname")
			}
			r.URL.Scheme = "http"
			return transport.RoundTrip(r)
		}), Timeout: 15 * time.Second, CheckRedirect: old(nil).CheckRedirect}
	}
	defer func() { blackstoneAPIClient = old }()
	if _, err := h.fetchDynamicConfig(context.Background(), "synthetic-node", "synthetic-token"); err == nil {
		t.Fatal("redirect accepted")
	}
	if hits != 1 {
		t.Fatal("redirect followed")
	}
	client := old(nil)
	if client.Timeout <= 0 || client.CheckRedirect == nil {
		t.Fatal("unbounded client")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBlackstoneProducerHeader(t *testing.T) {
	h, err := NewXHttp(XHttpOption{DeviceID: "synthetic-id", DeviceName: "synthetic-name"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(h.buildXHeader("synthetic-token"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] ^= xhttpPubKey[i%len(xhttpPubKey)]
	}
	var m map[string]string
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["X-IDENTIFIER"] != "synthetic-id" || m["X-DEVICE-NAME"] != "synthetic-name" || m["X-TOKEN"] != "synthetic-token" {
		t.Fatal("YAML device pair or token not consumed")
	}
	ts, err := strconv.ParseInt(m["X-TIMESTAMP"], 10, 64)
	if err != nil || ts < time.Now().Unix()-2 || ts > time.Now().Unix()+2 {
		t.Fatal("timestamp not dynamic seconds")
	}
	expected := map[string]string{"X-SOURCE": `{"mvjarp":"gp","sracun":"gp"}`, "X-CHECK-MOBILE": `{"isRoot":true,"isEmulator":false,"bundleID":"com.heysocks.android"}`, "X-BUNDLE-ID": "", "X-ABIS": "arm64-v8a,armeabi-v7a,armeabi", "X-INSTALLREFERRER": "unknown", "X-OS-VERSION": "30", "X-ISP": "", "X-COUNTRY-CODE": "CN", "X-LOADED": "false"}
	if len(m) != len(expected)+4 {
		t.Fatal("incomplete producer field set")
	}
	for k, v := range expected {
		if m[k] != v {
			t.Fatalf("producer mismatch: %s", k)
		}
	}
}
