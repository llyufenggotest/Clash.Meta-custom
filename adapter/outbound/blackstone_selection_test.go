package outbound

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

const selectionAliasYAML = `mode: rule
rules: ["DOMAIN,example.invalid,DIRECT", "MATCH,Primary"]
proxies:
 - {name: 日本#Bunny|transport-a, type: xhttp, server: 127.0.0.1, port: 4321, password: 'synthetic:00'}
 - {name: 日本#Other, type: xhttp, server: 192.0.2.1, port: 443, password: 'synthetic:00'}
proxy-groups:
 - {name: Primary, type: url-test, proxies: [日本#Bunny|transport-a]}
`

func TestBlackstoneSelectionAliasInitialize(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{Name: "日本#兔子", NodeID: "rabbit", DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneEnvelope(t, h, selectionAliasYAML)
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		b, _ := json.Marshal(map[string]string{"data": envelope})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}, nil
	})
	cfg, _, err := h.initialize(context.Background())
	if err != nil {
		t.Fatalf("exact response main group must bind UI alias without translation: %v", err)
	}
	if cfg.Name != "日本#Bunny|transport-a" || cfg.Port != "4321" {
		t.Fatal("wrong response leaf")
	}
}
