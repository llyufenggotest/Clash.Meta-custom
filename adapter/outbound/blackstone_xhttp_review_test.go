package outbound

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/json"
	C "github.com/metacubex/mihomo/constant"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// These intentionally assert required contracts, not the candidate's current output.
func TestReviewMissingUDPUsesOfficialZeroDefault(t *testing.T) {
	cfg, err := parseBlackstoneConfig(map[string]any{"server": "192.0.2.1", "port": 1, "password": "synthetic:00"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UDP {
		t.Fatal("missing udp became true; native newobject plus Decoder leaves omitted bool false")
	}
}
func TestReviewExplicitUDPFalseCapability(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) {})
	h.bestCfg.UDP = false
	_, err := h.ListenPacketContext(context.Background(), &C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 53})
	if err != C.ErrNotSupport {
		t.Fatal("udp:false did not reject", err)
	}
	if h.SupportUDP() {
		t.Fatal("selected udp:false rejects ListenPacketContext but advertises SupportUDP=true")
	}
}
func TestReviewSniffDestinationPreserved(t *testing.T) {
	got := make(chan []byte, 1)
	h := syntheticAdapter(t, func(c net.Conn) {
		c.SetDeadline(time.Now().Add(time.Second))
		frame, err := io.ReadAll(c)
		if err != nil {
			return
		}
		key := md5.Sum([]byte("synthetic-password"))
		block, _ := aes.NewCipher(key[:])
		plaintext := make([]byte, len(frame)-163)
		cipher.NewCTR(block, frame[147:163]).XORKeyStream(plaintext, frame[163:])
		got <- plaintext
	})
	conn, err := h.DialContext(context.Background(), &C.Metadata{Host: "original.invalid", SniffHost: "sniffed.invalid", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	want := append(append([]byte{3, 15}, []byte("sniffed.invalid")...), 1, 187)
	select {
	case plain := <-got:
		if !bytes.Equal(plain, want) {
			t.Fatal("destination no longer follows metadata.RuleHost for domain metadata")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer timeout")
	}
}
func TestReviewConfigExplicitUDPSemanticsAndCipherDefault(t *testing.T) {
	for _, udp := range []bool{false, true} {
		cfg, err := parseBlackstoneConfig(map[string]any{"server": "192.0.2.1", "port": 1, "password": "synthetic:00", "udp": udp})
		if err != nil || cfg.UDP != udp {
			t.Fatal("explicit UDP not preserved", err)
		}
		h := syntheticAdapter(t, func(net.Conn) {})
		h.bestCfg = cfg
		if _, _, _, err = h.transportSnapshot(); err != nil {
			t.Fatal("empty cipher default rejected", err)
		}
	}
}

// Go consumes independently generated Python fixtures in transport tests; adapter
// metadata here is synthetic and prints no endpoints, credentials, or plaintext.
func TestReviewSSFallbackCapability(t *testing.T) {
	h := syntheticAdapter(t, func(net.Conn) {})
	ss, err := NewShadowSocks(ShadowSocksOption{Name: "synthetic", Server: "192.0.2.1", Port: 1, Cipher: "aes-128-gcm", Password: "synthetic", UDP: false})
	if err != nil {
		t.Fatal(err)
	}
	h.ssOutbound = ss
	if h.SupportUDP() != ss.SupportUDP() {
		t.Fatal("selected SS capability not delegated")
	}
}
func TestReviewInnerConfigNoDiagnosticsLeak(t *testing.T) {
	cfg, err := parseBlackstoneConfig(map[string]any{"server": "192.0.2.1", "port": 1, "password": "synthetic:00", "fake-net": map[string]string{"tcp": "zz"}})
	if err != nil {
		t.Fatal(err)
	}
	h := syntheticAdapter(t, func(net.Conn) {})
	h.bestCfg = cfg
	_, _, _, err = h.transportSnapshot()
	if err == nil {
		t.Fatal("invalid fake accepted")
	}
	encoded, _ := json.Marshal(err.Error())
	if bytes.Contains(encoded, []byte("synthetic")) {
		t.Fatal("secret leaked")
	}
}
