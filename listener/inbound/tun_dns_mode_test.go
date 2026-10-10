package inbound

import "testing"

func TestTunInboundDNSModePropagation(t *testing.T) {
	for _, mode := range []string{"", "disabled", "native", "hijack"} {
		listener, err := NewTun(&TunOption{DNSMode: mode})
		if err != nil {
			t.Fatal(err)
		}
		if listener.tun.DNSMode != mode {
			t.Fatalf("inbound mode=%q want=%q", listener.tun.DNSMode, mode)
		}
		// Compare against copies of the normalized config so only dns-mode varies.
		same := *listener.config
		if !listener.config.Equal(same) {
			t.Fatal("equal mode must not reload")
		}
		changed := *listener.config
		changed.DNSMode = mode + "-changed"
		if listener.config.Equal(changed) {
			t.Fatal("changed mode must reload")
		}
	}
}
