package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"go.yaml.in/yaml/v3"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Only one selected existing identity/config POST; no login, subscription or device API.
// Trace records contain closed-vocabulary stages only, never private headers/body/config.
func TestBlackstoneAuthorizedControlBoundary(t *testing.T) {
	path := os.Getenv("BLACKSTONE_CONTROL_YAML")
	if path == "" {
		t.Skip("authorized existing YAML not supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("private YAML unavailable")
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		t.Fatal("private YAML invalid")
	}
	var option XHttpOption
	found := false
	for _, m := range doc.Proxies {
		if m["type"] != "Blackstone" {
			continue
		}
		option.Name, _ = m["name"].(string)
		option.Password, _ = m["password"].(string)
		option.NodeID, _ = m["node-id"].(string)
		option.DeviceID, _ = m["device_id"].(string)
		option.DeviceName, _ = m["device_name"].(string)
		found = true
		break
	}
	if !found || option.DeviceID == "" || option.DeviceName == "" || option.Password == "" || option.NodeID == "" {
		t.Fatal("existing canonical identity incomplete")
	}
	h, err := NewXHttp(option)
	if err != nil {
		t.Fatal("constructor failed")
	}
	defer h.Close()
	var mu sync.Mutex
	stages := []string{}
	mark := func(s string) { mu.Lock(); stages = append(stages, s); mu.Unlock() }
	trace := &httptrace.ClientTrace{
		ConnectStart: func(string, string) { mark("connect_start") },
		ConnectDone: func(_, _ string, e error) {
			if e == nil {
				mark("connect_ok")
			} else {
				mark("connect_failed")
			}
		},
		TLSHandshakeStart: func() { mark("tls_start") },
		TLSHandshakeDone: func(s tls.ConnectionState, e error) {
			if e != nil {
				mark("tls_failed")
			} else if s.NegotiatedProtocol == "h2" {
				mark("tls_verified_h2")
			} else {
				mark("tls_verified_http1")
			}
		},
		GotConn: func(httptrace.GotConnInfo) { mark("got_connection") },
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err == nil {
				mark("request_written")
			} else {
				mark("request_write_failed")
			}
		},
		GotFirstResponseByte: func() { mark("first_response_byte") },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	configs, err := h.fetchDynamicConfig(httptrace.WithClientTrace(ctx, trace), option.NodeID, option.Password)
	mu.Lock()
	snapshot := append([]string(nil), stages...)
	mu.Unlock()
	t.Logf("boundary=Windows-not-Fujian-or-iOS stages=%v", snapshot)
	if err != nil {
		class := "redacted"
		switch {
		case errors.Is(err, context.Canceled):
			class = "canceled"
		case errors.Is(err, context.DeadlineExceeded):
			class = "deadline"
		case strings.Contains(err.Error(), "EOF"):
			class = "EOF"
		case strings.Contains(err.Error(), "reset"):
			class = "reset"
		}
		t.Fatalf("control boundary class=%s", class)
	}
	t.Logf("control config accepted node_count=%d", len(configs))
}
