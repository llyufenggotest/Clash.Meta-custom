package outbound

import (
	"strings"
	"testing"
)

func TestBlackstoneSelectionCannotHideUnauditedMemberBehindMatchedFalse(t *testing.T) {
	d := selectionDocument(t)
	p := d["proxies"].([]any)[0].(map[string]any)
	p["type"] = "future"
	p["matched"] = false
	d["proxy-groups"].([]any)[0].(map[string]any)["proxies"] = []any{p["name"], "日本#Other"}
	h := &XHttp{}
	got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
	if err == nil || got != nil || !strings.Contains(err.Error(), "stage=node-capability") {
		t.Fatal("main-group member was silently dropped behind legacy matched hint")
	}
}
