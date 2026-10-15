package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestReviewSelectionInvalidTransportFields(t *testing.T) {
	for _, item := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"ss-unsupported-cipher", func(p map[string]any) {
			p["type"] = "ss"
			p["cipher"] = "review-unsupported-cipher"
			p["password"] = "synthetic"
		}},
		{"ss-nonstring-cipher", func(p map[string]any) { p["type"] = "ss"; p["cipher"] = 42; p["password"] = "synthetic" }},
		{"xhttp-malformed-password", func(p map[string]any) { p["password"] = "synthetic-no-colon" }},
	} {
		t.Run(item.name, func(t *testing.T) {
			d := selectionDocument(t)
			p := d["proxies"].([]any)[0].(map[string]any)
			item.mutate(p)
			d["proxy-groups"].([]any)[0].(map[string]any)["proxies"] = []any{p["name"], "日本#Other"}
			h := &XHttp{}
			got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
			if err == nil || got != nil || !strings.Contains(err.Error(), "stage=node-capability") {
				t.Errorf("BLOCK: invalid selected transport accepted before race; converted=%d err_present=%v", len(got), err != nil)
			}
		})
	}
}

func TestReviewSelectionCertificateInnerRequiredFields(t *testing.T) {
	h := &XHttp{}
	inner, _ := json.Marshal(map[string]any{"type": "xhttp", "certificate": "synthetic-nested"})
	wrapped := fixtureBlackstoneEnvelope(t, h, string(inner))
	raw, _ := base64.StdEncoding.DecodeString(wrapped)
	for i := range raw {
		raw[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	var outer struct {
		Data map[string]string `json:"data"`
	}
	json.Unmarshal(raw, &outer)
	packed, _ := base64.StdEncoding.DecodeString(outer.Data["smart"])
	d := selectionDocument(t)
	p := d["proxies"].([]any)[0].(map[string]any)
	p["certificate"] = base64.StdEncoding.EncodeToString(append(make([]byte, 48), packed...))
	got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
	if err == nil || got != nil {
		t.Errorf("BLOCK: inner certificate bypassed required endpoint/password; converted=%d err_present=%v", len(got), err != nil)
	}
}

func TestReviewSelectionInvalidSSSubstitutedAtInitialize(t *testing.T) {
	d := selectionDocument(t)
	p := d["proxies"].([]any)[0].(map[string]any)
	p["type"] = "ss"
	p["cipher"] = "review-unsupported-cipher"
	p["password"] = "synthetic"
	p["server"] = "loser"
	p["port"] = 1
	q := d["proxies"].([]any)[1].(map[string]any)
	q["server"] = "winner"
	q["port"] = 1
	d["proxy-groups"].([]any)[0].(map[string]any)["proxies"] = []any{p["name"], q["name"]}
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	h.dialer = &blackstoneRaceDialer{done: make(chan struct{})}
	envelope := fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d))
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
	})
	cfg, ss, err := h.initialize(context.Background())
	if ss != nil {
		ss.Close()
	}
	if err == nil {
		t.Errorf("BLOCK: invalid selected SS lost health race and alternate returned; alternate_selected=%v", cfg.Name == q["name"])
	}
}

func TestReviewSelectionSSConstructorFailureRedaction(t *testing.T) {
	d := selectionDocument(t)
	p := d["proxies"].([]any)[0].(map[string]any)
	p["type"] = "ss"
	p["server"] = "redaction-sentinel.invalid"
	p["cipher"] = "review-unsupported-cipher"
	p["password"] = "synthetic"
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d))
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
	})
	_, _, err := h.initialize(context.Background())
	if err == nil || !strings.Contains(err.Error(), "stage=node-capability") || strings.Contains(err.Error(), "redaction-sentinel") {
		t.Errorf("BLOCK: selected SS constructor failure not safe node-capability; error_present=%v endpoint_in_error=%v node_capability_stage=%v", err != nil, err != nil && strings.Contains(err.Error(), "redaction-sentinel"), err != nil && strings.Contains(err.Error(), "stage=node-capability"))
	}
}

func TestReviewSelectionRequiredFields(t *testing.T) {
	for _, field := range []string{"server", "port", "password"} {
		for _, bad := range []any{nil, "", true, []any{"synthetic"}} {
			d := selectionDocument(t)
			p := d["proxies"].([]any)[0].(map[string]any)
			p[field] = bad
			h := &XHttp{}
			got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
			if err == nil || got != nil {
				t.Errorf("required field rejected incorrectly: %s", field)
			}
		}
	}
}

func TestReviewSelectionBaselineAlias(t *testing.T) {
	const plain = `mode: rule
rules: ["MATCH,Primary"]
proxies:
 - {name: 日本#Bunny|a, type: xhttp, server: 127.0.0.1, port: 4321, password: 'synthetic:00'}
 - {name: 日本#Other, type: xhttp, server: 127.0.0.1, port: 4322, password: 'synthetic:00'}
proxy-groups:
 - {name: Primary, type: url-test, proxies: [日本#Bunny|a]}
`
	h, _ := NewXHttp(XHttpOption{Name: "日本#兔子", NodeID: "synthetic", DeviceID: "synthetic", DeviceName: "synthetic"})
	envelope := fixtureBlackstoneEnvelope(t, h, plain)
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
	})
	cfg, _, err := h.initialize(context.Background())
	if err != nil || cfg.Name != "日本#Bunny|a" {
		t.Fatal("exact response alias contract not implemented")
	}
}
