package outbound

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestReviewFixCapabilityGenerationPublication(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) {})
	disabled, err := NewShadowSocks(ShadowSocksOption{Name: "synthetic", Server: "127.0.0.1", Port: 1, Cipher: "aes-128-gcm", Password: "synthetic", UDP: false, UDPOverTCP: true})
	if err != nil {
		t.Fatal("fixture constructor")
	}
	defer disabled.Close()
	enabled, err := NewShadowSocks(ShadowSocksOption{Name: "synthetic", Server: "127.0.0.1", Port: 1, Cipher: "aes-128-gcm", Password: "synthetic", UDP: true, UDPOverTCP: true})
	if err != nil {
		t.Fatal("fixture constructor")
	}
	defer enabled.Close()
	for _, tc := range []struct {
		name                  string
		initialized, udp, uot bool
		ss                    C.ProxyAdapter
		wantUDP, wantUOT      bool
	}{
		{name: "unknown", udp: true, uot: true},
		{name: "native-disabled", initialized: true},
		{name: "native", initialized: true, udp: true, wantUDP: true},
		{name: "native-uot", initialized: true, udp: true, uot: true, wantUDP: true, wantUOT: true},
		{name: "ss-disabled-ignores-native", initialized: true, udp: true, uot: true, ss: disabled},
		{name: "ss-enabled-ignores-native", initialized: true, ss: enabled, wantUDP: true, wantUOT: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.initMu.Lock()
			h.isInit = tc.initialized
			h.bestCfg.UDP = tc.udp
			h.bestCfg.UDPOverTCP = tc.uot
			h.ssOutbound = tc.ss
			h.initMu.Unlock()
			if h.SupportUDP() != tc.wantUDP || h.SupportUOT() != tc.wantUOT {
				t.Fatal("capabilities not from current published generation")
			}
		})
	}
	// Exercise the same lock as successful initialization and reset. Under race,
	// readers must never observe unsynchronized fields/delegate publication.
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				h.SupportUDP()
				h.SupportUOT()
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		h.initMu.Lock()
		h.isInit = i%2 == 0
		h.bestCfg.UDP = i%3 == 0
		h.ssOutbound = nil
		if i%5 == 0 {
			h.ssOutbound = enabled
		}
		h.initMu.Unlock()
	}
	wg.Wait()
}

func TestReviewFixSniffLengthStillValidated(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) { t.Error("invalid destination dialed") })
	dialer := &reviewCountingDialer{blackstoneWireDialer: blackstoneWireDialer{serve: func(net.Conn) {}}}
	h.dialer = dialer
	_, err := h.DialContext(context.Background(), &C.Metadata{Host: "original.invalid", SniffHost: strings.Repeat("x", 256), DstPort: 443})
	if err == nil || dialer.calls.Load() != 0 {
		t.Fatal("invalid RuleHost bypassed pre-dial validation")
	}
}

func TestReviewFixLegacySelectedCapabilityBoundary(t *testing.T) {
	// Legacy conversion remains permissive: only the exact device path performs
	// set-wide constructor validation. These configs are not dialed.
	d := selectionDocument(t)
	p := d["proxies"].([]any)[0].(map[string]any)
	p["type"] = "ss"
	p["cipher"] = 42
	p["password"] = "synthetic"
	h := &XHttp{}
	got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), false)
	if err != nil || len(got) == 0 || got[0].Cipher != "2022-blake3-aes-128-gcm" {
		t.Fatal("legacy conversion contract changed")
	}
}

func TestReviewFixExactSSCapabilityOptions(t *testing.T) {
	d := selectionDocument(t)
	p := d["proxies"].([]any)[0].(map[string]any)
	p["type"] = "ss"
	p["cipher"] = "aes-128-gcm"
	p["password"] = "synthetic"
	p["udp"] = true
	p["udp-over-tcp"] = true
	p["udp-over-tcp-version"] = 1
	h := &XHttp{}
	got, err := h.processBlackstoneSelectionData(fixtureBlackstoneEnvelope(t, h, selectionYAML(t, d)), true)
	if err != nil || len(got) != 1 {
		t.Fatal("constructable exact SS rejected")
	}
	cfg := got[0]
	if !cfg.UDP || !cfg.UDPOverTCP || cfg.UDPOverTCPVersion != 1 {
		t.Fatal("SS capability fields lost during conversion")
	}
	ss, err := blackstoneSelectedSS(cfg, BasicOption{}, "synthetic")
	if err != nil {
		t.Fatal("exact SS constructor")
	}
	defer ss.Close()
	h.isInit = true
	h.lastFetch = time.Now()
	h.bestCfg = cfg
	h.ssOutbound = ss
	if !h.SupportUDP() || !h.SupportUOT() {
		t.Fatal("constructed delegate capability mismatch")
	}
}
