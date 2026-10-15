package outbound

import (
	"testing"
	"time"
)

func TestTCPProbeDelaySaturatesWithoutSentinelOrWrap(t *testing.T) {
	for _, tc := range []struct {
		elapsed time.Duration
		want    uint16
	}{
		{0, 1}, {time.Microsecond, 1}, {time.Millisecond, 1}, {42 * time.Millisecond, 42},
		{65534 * time.Millisecond, 65534}, {65535 * time.Millisecond, 65534},
		{65536 * time.Millisecond, 65534}, {time.Hour, 65534},
	} {
		if got := tcpProbeDelay(tc.elapsed); got != tc.want {
			t.Errorf("%s: got %d want %d", tc.elapsed, got, tc.want)
		}
	}
}
