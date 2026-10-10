package route

import (
	"encoding/json"
	LC "github.com/metacubex/mihomo/listener/config"
	"testing"
)

func TestTunDNSModePatchPreserveSetAndClear(t *testing.T) {
	for _, tc := range []struct{ payload, want string }{{`{}`, "native"}, {`{"dns-mode":"hijack"}`, "hijack"}, {`{"dns-mode":""}`, ""}, {`{"dns-mode":"disabled"}`, "disabled"}} {
		var patch tunSchema
		if err := json.Unmarshal([]byte(tc.payload), &patch); err != nil {
			t.Fatal(err)
		}
		got := pointerOrDefaultTun(&patch, LC.Tun{DNSMode: "native"})
		if got.DNSMode != tc.want {
			t.Fatalf("patch %s: got=%q want=%q", tc.payload, got.DNSMode, tc.want)
		}
	}
}
