package outbound

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Opt-in offline input only: never emits endpoints, passwords, tokens or plaintext.
func TestBlackstoneSelectionOfficialOffline(t *testing.T) {
	path := os.Getenv("BLACKSTONE_OFFLINE_CAPTURE")
	if path == "" {
		t.Skip("set BLACKSTONE_OFFLINE_CAPTURE to retained capture; no network")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("capture unavailable")
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) < 27 {
		t.Fatal("capture shape")
	}
	encoded := strings.TrimSpace(lines[26])
	var wrapper map[string]any
	if json.Unmarshal([]byte(encoded), &wrapper) == nil {
		encoded, _ = wrapper["data"].(string)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded + strings.Repeat("=", (4-len(encoded)%4)%4))
	if err != nil {
		t.Fatal("envelope encoding")
	}
	for i := range raw {
		raw[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	if bytes.HasPrefix(raw, []byte{31, 139}) {
		raw, err = gunzipLimited(raw)
		if err != nil {
			t.Fatal("envelope gzip")
		}
	}
	var outer struct {
		Data map[string]any `json:"data"`
	}
	if json.Unmarshal(raw, &outer) != nil {
		t.Fatal("envelope shape")
	}
	h := &XHttp{}
	s, _ := outer.Data["smart"].(string)
	packed, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal("layer encoding")
	}
	plain, err := h.decryptBlackstonePayload(packed)
	if err != nil {
		t.Fatal("layer decrypt")
	}
	selected, err := blackstoneDecodeSelection(plain)
	if err != nil {
		t.Fatalf("full official SMART routing contract rejected: %v", err)
	}
	var doc blackstoneSelectionDocument
	if yaml.Unmarshal(plain, &doc) != nil {
		t.Fatal("document format")
	}
	t.Logf("full official SMART routing PASS candidates=%d selected=%d rules=%d groups=%d (not projected)", len(doc.Proxies), len(selected), len(doc.Rules), len(doc.Groups))
	if len(doc.Proxies) != 10 || len(selected) != 2 {
		t.Fatal("official HK capture expected 10 total / 2 main leaves")
	}
	converted, err := h.processBlackstoneSelectionData(encoded, true)
	if err != nil || len(converted) != len(selected) {
		t.Fatal("official selected certificate conversion failed")
	}
	for i, c := range converted {
		if c.Name != selected[i]["name"] {
			t.Fatal("official certificate outer reference changed")
		}
	}
	t.Log("full official SMART exact selection and certificate conversion PASS")
	for i, p := range selected {
		if p["name"] != doc.Proxies[8+i]["name"] {
			t.Fatal("main leaves differ from official indices 8,9")
		}
	}
	if out := os.Getenv("BLACKSTONE_SANITIZED_FIXTURE_OUT"); out != "" {
		// Keep mode, every rule and every complete group; replace proxy transport
		// payloads with synthetic equivalents only. No routing-option projection.
		var full map[string]any
		if yaml.Unmarshal(plain, &full) != nil {
			t.Fatal("full format")
		}
		proxies := make([]map[string]any, len(doc.Proxies))
		for i, p := range doc.Proxies {
			proxies[i] = map[string]any{"name": p["name"], "type": "xhttp", "server": "192.0.2.1", "port": 4321, "password": "synthetic:00"}
		}
		// Only routing contract and synthetic proxies belong in a shareable fixture.
		safe := map[string]any{"mode": full["mode"], "rules": full["rules"], "proxy-groups": full["proxy-groups"], "proxies": proxies}
		b, err := yaml.Marshal(safe)
		if err != nil {
			t.Fatal("sanitize")
		}
		if err = os.WriteFile(out, b, 0600); err != nil {
			t.Fatal("fixture write")
		}
	}
}

func TestBlackstoneSelectionRuntimeOffline(t *testing.T) {
	paths := os.Getenv("BLACKSTONE_OFFLINE_RUNTIME")
	if paths == "" {
		t.Skip("set BLACKSTONE_OFFLINE_RUNTIME to semicolon-separated retained plaintexts")
	}
	for i, path := range strings.Split(paths, ";") {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("runtime unavailable")
		}
		selected, err := blackstoneDecodeSelection(b)
		if err != nil {
			t.Fatalf("full runtime %d routing contract rejected: %v", i, err)
		}
		converted, conversionErr := (&XHttp{}).processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, &XHttp{}, string(b)), true)
		unsupported := false
		for _, p := range selected {
			if p["type"] != "xhttp" && p["type"] != "ss" {
				unsupported = true
			}
		}
		if unsupported {
			if conversionErr == nil || converted != nil || !strings.Contains(conversionErr.Error(), "stage=node-capability") {
				t.Fatal("unaudited runtime transport was filtered or substituted")
			}
			t.Logf("runtime %d unaudited transport correctly fails closed at node-capability (selection remains proven)", i)
		} else if conversionErr != nil || len(converted) != len(selected) {
			t.Fatal("audited runtime conversion failed")
		}
		var doc blackstoneSelectionDocument
		if yaml.Unmarshal(b, &doc) != nil || len(selected) == 0 {
			t.Fatal("runtime structure")
		}
		// Compare Bunny runtime's complete names with retained response shape
		// privately; never emit endpoint-bearing names or identity material.
		if shapePath := os.Getenv("BLACKSTONE_OFFLINE_RESPONSE_SHAPE"); shapePath != "" && strings.Contains(path, "b6e9f3eec04ab7693641f2c9ac77d066eb76171f9c5f32959ad4c0d853cc082d") {
			sb, e := os.ReadFile(shapePath)
			if e != nil {
				t.Fatal("response shape unavailable")
			}
			var shapes map[string]json.RawMessage
			if json.Unmarshal(sb, &shapes) != nil {
				t.Fatal("response shape format")
			}
			var shape struct {
				Layers map[string]json.RawMessage `json:"layers"`
			}
			if json.Unmarshal(shapes["日本#兔子"], &shape) != nil {
				t.Fatal("Bunny response shape format")
			}
			var smart struct {
				Proxies []struct {
					Name string `json:"name"`
				} `json:"proxies"`
			}
			if json.Unmarshal(shape.Layers["smart"], &smart) != nil {
				t.Fatal("Bunny SMART response shape format")
			}
			leaves := smart.Proxies
			if len(leaves) != 2 || len(selected) != 1 {
				t.Fatal("Bunny response/runtime count mismatch")
			}
			for _, p := range selected {
				found := false
				for _, q := range leaves {
					if p["name"] == q.Name {
						found = true
					}
				}
				if !found {
					t.Fatal("Bunny runtime is not an exact response member")
				}
			}
			t.Log("Bunny runtime exact response-member correlation PASS (no alias translation)")
		}
		t.Logf("full official runtime %d routing PASS candidates=%d selected=%d rules=%d groups=%d (all main-group fields retained)", i, len(doc.Proxies), len(selected), len(doc.Rules), len(doc.Groups))
	}
}
