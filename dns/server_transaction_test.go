package dns

import (
	"net"
	"testing"
)

func TestDNSLifecycleRejectedReplacementPreservesGenerationAndIntent(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			StopServer()
			_ = ResumeServer()
			defer func() { StopServer(); _ = ResumeServer() }()
			oldAddr, nextAddr := lifecycleAddress(t), lifecycleAddress(t)
			lc, svc := &net.ListenConfig{}, &lifecycleService{}
			if err := ReplaceServerWithError(oldAddr, lc, svc); err != nil {
				t.Fatal(err)
			}
			old := server
			var closeBlocker func() error
			if network == "tcp" {
				b, err := net.Listen("tcp", nextAddr)
				if err != nil {
					t.Fatal(err)
				}
				closeBlocker = b.Close
			} else {
				b, err := net.ListenPacket("udp", nextAddr)
				if err != nil {
					t.Fatal(err)
				}
				closeBlocker = b.Close
			}
			defer closeBlocker()
			if err := ReplaceServerWithError(nextAddr, &net.ListenConfig{}, &lifecycleService{}); err == nil {
				t.Fatal("busy candidate admitted")
			}
			if server != old || address != oldAddr || desiredAddress != oldAddr || desiredListenConfig != lc || desiredService != svc || server.service != svc {
				t.Fatal("failure changed old generation/service/intent")
			}
			lifecycleAssertQueries(t, oldAddr)
			closeBlocker()
			if err := ResumeServer(); err != nil {
				t.Fatal(err)
			}
			lifecycleAssertQueries(t, oldAddr)
			lifecycleAssertFree(t, nextAddr)
			// Reuse the live same-address socket pair rather than colliding with self.
			nextSvc := &lifecycleService{}
			if err := ReplaceServerWithError(oldAddr, lc, nextSvc); err != nil {
				t.Fatal(err)
			}
			if server != old || server.service != nextSvc {
				t.Fatal("same-address admission lost generation/service")
			}
			if err := ReplaceServerWithError(nextAddr, lc, nextSvc); err != nil {
				t.Fatal(err)
			}
			lifecycleAssertQueries(t, nextAddr)
			lifecycleAssertFree(t, oldAddr)
		})
	}
}

func TestDNSLifecycleReplacementInvalidAddressPreservesIntent(t *testing.T) {
	StopServer()
	_ = ResumeServer()
	defer StopServer()
	addr := lifecycleAddress(t)
	if err := ReplaceServerWithError(addr, &net.ListenConfig{}, &lifecycleService{}); err != nil {
		t.Fatal(err)
	}
	prior := server
	if err := ReplaceServerWithError("invalid-address", &net.ListenConfig{}, &lifecycleService{}); err == nil {
		t.Fatal("invalid listener admitted")
	}
	if server != prior || desiredAddress != addr {
		t.Fatal("invalid candidate changed intent")
	}
	lifecycleAssertQueries(t, addr)
}
