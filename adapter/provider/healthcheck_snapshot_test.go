package provider

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/common/utils"
)

func TestHealthCheckSetProxiesCopiesInput(t *testing.T) {
	hc := NewHealthCheck(nil, "", 0, 0, true, utils.IntRanges[uint16]{})
	defer hc.close()

	input := make([]C.Proxy, 1)
	hc.setProxies(input)
	input[0] = nil

	hc.mu.Lock()
	got := len(hc.proxies)
	hc.mu.Unlock()
	if got != 1 {
		t.Fatalf("stored proxy count = %d, want 1", got)
	}
}
