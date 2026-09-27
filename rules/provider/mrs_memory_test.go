package provider

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"runtime"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestMrsDecodeLargeFullFidelity(t *testing.T) {
	for _, behavior := range []P.RuleBehavior{P.Domain, P.IPCIDR} {
		t.Run(behavior.String(), func(t *testing.T) {
			const n = 12000
			built := newStrategy(behavior, nil)
			built.Reset()
			metadata := make([]*C.Metadata, n)
			for i := 0; i < n; i++ {
				if behavior == P.Domain {
					host := fmt.Sprintf("%x.example", sha256.Sum256([]byte(fmt.Sprint(i))))
					built.Insert("+." + host)
					metadata[i] = metadataForHost("sub." + host)
				} else {
					ip := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
					built.Insert(ip.String() + "/32")
					metadata[i] = &C.Metadata{DstIP: ip}
				}
			}
			built.FinishInsert()
			var compressed bytes.Buffer
			if err := WriteMrsFromStrategy(&compressed, behavior, built.(mrsRuleStrategy)); err != nil {
				t.Fatal(err)
			}
			oldProcs := runtime.GOMAXPROCS(4)
			defer runtime.GOMAXPROCS(oldProcs)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			loaded, err := rulesMrsParse(compressed.Bytes(), newStrategy(behavior, nil))
			runtime.ReadMemStats(&after)
			if err != nil {
				t.Fatal(err)
			}
			allocated := after.TotalAlloc - before.TotalAlloc
			t.Logf("%s decode allocation = %d bytes", behavior, allocated)
			if maxLowMemoryRuleCount > 0 && behavior == P.Domain && allocated > 12<<20 {
				t.Fatalf("low-memory decoder allocated %d bytes; want <=12 MiB for this fixture", allocated)
			}
			if loaded.Count() != n {
				t.Fatal("count changed")
			}
			for _, m := range metadata {
				if !loaded.Match(m, C.RuleMatchHelper{}) {
					t.Fatalf("missing rule %v", m)
				}
			}
			if loaded.Match(&C.Metadata{Host: "absent.example", DstIP: netip.MustParseAddr("192.0.2.1")}, C.RuleMatchHelper{}) {
				t.Fatal("unexpected match")
			}
			if _, err := rulesMrsParse(compressed.Bytes()[:compressed.Len()/2], newStrategy(behavior, nil)); err == nil {
				t.Fatal("truncated MRS accepted")
			}
		})
	}
}
