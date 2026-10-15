package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"go.yaml.in/yaml/v3"
)

func selectionDocument(t *testing.T) map[string]any {
	t.Helper()
	var d map[string]any
	if err := yaml.Unmarshal([]byte(selectionAliasYAML), &d); err != nil {
		t.Fatal(err)
	}
	return d
}
func selectionYAML(t *testing.T, d map[string]any) string {
	t.Helper()
	b, err := yaml.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBlackstoneSelectionExactMembers(t *testing.T) {
	d := selectionDocument(t)
	proxies := d["proxies"].([]any)
	second := map[string]any{"name": "日本#Bunny|transport-b", "type": "xhttp", "server": "192.0.2.2", "port": 4322, "password": "synthetic:00"}
	d["proxies"] = append(proxies, second)
	g := d["proxy-groups"].([]any)[0].(map[string]any)
	g["once-check"] = 3
	g["proxies"] = []any{second["name"], proxies[0].(map[string]any)["name"]}
	h := &XHttp{}
	got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != second["name"] || got[0].Port != "4322" || got[1].Port != "4321" {
		t.Fatal("must preserve exact member order, distinct addresses and all transports; exclude other business leaves")
	}
}

func TestBlackstoneSelectionRejectsUnprovedMembership(t *testing.T) {
	cases := map[string]func(map[string]any){
		"missing-mode":         func(d map[string]any) { delete(d, "mode") },
		"global":               func(d map[string]any) { d["mode"] = "global" },
		"missing-rules":        func(d map[string]any) { delete(d, "rules") },
		"missing-match":        func(d map[string]any) { d["rules"] = []string{"DOMAIN,example.invalid,Primary"} },
		"early-match":          func(d map[string]any) { d["rules"] = []string{"MATCH,Primary", "DOMAIN,example.invalid,DIRECT"} },
		"multiple-match":       func(d map[string]any) { d["rules"] = []string{"MATCH,Primary", "MATCH,Primary"} },
		"match-options":        func(d map[string]any) { d["rules"] = []string{"MATCH,Primary,no-resolve"} },
		"direct-target":        func(d map[string]any) { d["rules"] = []string{"MATCH,DIRECT"} },
		"missing-group":        func(d map[string]any) { delete(d, "proxy-groups") },
		"duplicate-group":      func(d map[string]any) { a := d["proxy-groups"].([]any); d["proxy-groups"] = append(a, a[0]) },
		"duplicate-leaf":       func(d map[string]any) { a := d["proxies"].([]any); d["proxies"] = append(a, a[0]) },
		"group-leaf-collision": func(d map[string]any) { d["proxies"].([]any)[1].(map[string]any)["name"] = "Primary" },
		"reserved-leaf":        func(d map[string]any) { d["proxies"].([]any)[1].(map[string]any)["name"] = "DIRECT" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := selectionDocument(t)
			mutate(d)
			if _, err := blackstoneDecodeSelection([]byte(selectionYAML(t, d))); err == nil {
				t.Fatal("unproved selection accepted")
			}
		})
	}
	groupCases := map[string]map[string]any{
		"empty": {"proxies": []any{}}, "dangling": {"proxies": []any{"missing"}},
		"substring": {"proxies": []any{"日本#Bunny"}}, "nonarray": {"proxies": "日本#Bunny|transport-a"},
		"nonstring": {"proxies": []any{42}}, "duplicate-member": {"proxies": []any{"日本#Bunny|transport-a", "日本#Bunny|transport-a"}},
		"direct": {"proxies": []any{"DIRECT"}}, "reject": {"proxies": []any{"REJECT"}},
		"self-cycle": {"proxies": []any{"Primary"}}, "select": {"type": "select"}, "fallback": {"type": "fallback"},
		"unknown-type": {"type": "future"}, "provider": {"use": []any{"remote"}}, "filter": {"filter": ".*"},
		"include-all": {"include-all": false}, "include-all-proxies": {"include-all-proxies": true},
		"exclude-filter": {"exclude-filter": "other"}, "exclude-type": {"exclude-type": "vless"},
		"missing-member-field": {"proxies": nil},
		"unknown-option":       {"future": false}, "once-type": {"once-check": "3"}, "once-negative": {"once-check": -1},
		"once-bound": {"once-check": 86401}, "nested": {"proxies": []any{"Nested"}},
	}
	for name, fields := range groupCases {
		t.Run(name, func(t *testing.T) {
			d := selectionDocument(t)
			a := d["proxy-groups"].([]any)
			g := a[0].(map[string]any)
			for k, v := range fields {
				g[k] = v
			}
			d["proxy-groups"] = append(a, map[string]any{"name": "Nested", "type": "url-test", "proxies": []any{"日本#Bunny|transport-a"}})
			if _, err := blackstoneDecodeSelection([]byte(selectionYAML(t, d))); err == nil {
				t.Fatal("unproved main group accepted")
			}
		})
	}
	for name, suffix := range map[string]string{"duplicate-key": "mode: rule\n", "extra-document": "---\nmode: rule\n", "alias": "unused: &anchor x\nother: *anchor\n", "merge": "unused: {<<: {x: 1}}\n"} {
		t.Run(name, func(t *testing.T) {
			if _, err := blackstoneDecodeSelection([]byte(selectionAliasYAML + suffix)); err == nil {
				t.Fatal("YAML indirection/ambiguity accepted")
			}
		})
	}
}

func TestBlackstoneSelectionUnsupportedMemberFailsWholeResponse(t *testing.T) {
	for _, typ := range []string{"future-vless-successor", "os", "future", ""} {
		t.Run("type-"+typ, func(t *testing.T) {
			d := selectionDocument(t)
			d["proxies"].([]any)[0].(map[string]any)["type"] = typ
			g := d["proxy-groups"].([]any)[0].(map[string]any)
			g["proxies"] = []any{"日本#Bunny|transport-a", "日本#Other"}
			h := &XHttp{}
			cfg, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
			if err == nil || cfg != nil || !strings.Contains(err.Error(), "stage=node-capability") {
				t.Fatal("unsupported selected member must fail, not filter or substitute another leaf")
			}
		})
	}
}

func TestBlackstoneSelectionMissingSelectedEndpointFailsWholeResponse(t *testing.T) {
	d := selectionDocument(t)
	delete(d["proxies"].([]any)[0].(map[string]any), "server")
	g := d["proxy-groups"].([]any)[0].(map[string]any)
	g["proxies"] = []any{"日本#Bunny|transport-a", "日本#Other"}
	h := &XHttp{}
	cfg, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
	if err == nil || cfg != nil || !strings.Contains(err.Error(), "stage=node-capability") {
		t.Fatal("invalid selected transport must fail whole response before health selection")
	}
}

func TestBlackstoneSelectionCertificateOuterReference(t *testing.T) {
	for _, typ := range []string{"xhttp", "vless", ""} {
		t.Run("inner-"+typ, func(t *testing.T) {
			h := &XHttp{}
			inner, _ := json.Marshal(map[string]any{"name": "unrelated-inner-display", "type": typ, "server": "127.0.0.1", "port": 4321, "password": "synthetic:00"})
			wrapped := fixtureBlackstoneEnvelope(t, h, string(inner))
			raw, _ := base64.StdEncoding.DecodeString(wrapped)
			for i := range raw {
				raw[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
			}
			var outer struct {
				Data map[string]string `json:"data"`
			}
			if json.Unmarshal(raw, &outer) != nil {
				t.Fatal("fixture envelope")
			}
			packed, _ := base64.StdEncoding.DecodeString(outer.Data["smart"])
			d := selectionDocument(t)
			p := d["proxies"].([]any)[0].(map[string]any)
			p["certificate"] = base64.StdEncoding.EncodeToString(append(make([]byte, 48), packed...))
			got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
			if typ != "xhttp" {
				if err == nil || got != nil {
					t.Fatal("unaudited certificate type accepted")
				}
				return
			}
			if err != nil || len(got) != 1 || got[0].Name != p["name"] {
				t.Fatal("certificate must preserve exact outer candidate reference")
			}
		})
	}
}

func TestBlackstoneSelectionRequestScoped(t *testing.T) {
	// Each intercepted POST selects its own envelope; no identities or real network.
	h1, _ := NewXHttp(XHttpOption{Name: "same display", NodeID: "request-a", DeviceID: "synthetic", DeviceName: "synthetic"})
	h2, _ := NewXHttp(XHttpOption{Name: "same display", NodeID: "request-b", DeviceID: "synthetic", DeviceName: "synthetic"})
	docs := map[string]string{}
	for i, id := range []string{"request-a", "request-b"} {
		d := selectionDocument(t)
		p := d["proxies"].([]any)[0].(map[string]any)
		p["name"] = fmt.Sprintf("exact-%d", i)
		p["port"] = 4321 + i
		d["proxy-groups"].([]any)[0].(map[string]any)["proxies"] = []any{p["name"]}
		docs[id] = fixtureBlackstoneEnvelope(t, h1, selectionYAML(t, d))
	}
	var mu sync.Mutex
	calls := map[string]int{}
	fixtureBlackstoneClient(t, func(r *http.Request) (*http.Response, error) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(req["data"])
		if err != nil {
			return nil, err
		}
		for i := range b {
			b[i] ^= xhttpPubKey[i%len(xhttpPubKey)]
		}
		var body map[string]any
		if err = json.Unmarshal(b, &body); err != nil {
			return nil, err
		}
		id, _ := body["id"].(string)
		mu.Lock()
		calls[id]++
		mu.Unlock()
		encoded, ok := docs[id]
		if !ok {
			return nil, fmt.Errorf("unexpected synthetic request")
		}
		return blackstoneResponse(`{"data":"` + encoded + `"}`), nil
	})
	var wg sync.WaitGroup
	for i, h := range []*XHttp{h1, h2} {
		wg.Add(1)
		go func(i int, h *XHttp) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				cfg, _, err := h.initialize(context.Background())
				if err != nil || cfg.Name != fmt.Sprintf("exact-%d", i) || cfg.Port != fmt.Sprint(4321+i) {
					t.Error("request result leaked across adapter/node-id boundary")
					return
				}
			}
		}(i, h)
	}
	wg.Wait()
	if !reflect.DeepEqual(calls, map[string]int{"request-a": 10, "request-b": 10}) {
		t.Fatal("request/result provenance not preserved")
	}
}
