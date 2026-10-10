package loopback

import (
	"errors"
	C "github.com/metacubex/mihomo/constant"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
)

type trackedConn struct {
	C.Conn
	local  net.Addr
	closed bool
}

func (c *trackedConn) LocalAddr() net.Addr { return c.local }
func (c *trackedConn) Close() error        { c.closed = true; return nil }

type trackedPacketConn struct {
	C.PacketConn
	local  net.Addr
	closed bool
}

func (c *trackedPacketConn) LocalAddr() net.Addr { return c.local }
func (c *trackedPacketConn) Close() error        { c.closed = true; return nil }

func TestDetectorDefaultHonorsOnlyEnvironment(t *testing.T) {
	wantDisabled, _ := strconv.ParseBool(os.Getenv("DISABLE_LOOPBACK_DETECTOR"))
	if (NewDetector() == nil) != wantDisabled {
		t.Fatal("platform silently overrides DISABLE_LOOPBACK_DETECTOR")
	}
}

func TestDetectorTCPAndUDPReleaseOnClose(t *testing.T) {
	old := disableLoopBackDetector
	disableLoopBackDetector = false
	defer func() { disableLoopBackDetector = old }()
	detector := NewDetector()
	metadata := &C.Metadata{SrcIP: netip.MustParseAddr("127.0.0.1"), SrcPort: 12345}
	rawTCP := &trackedConn{local: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	tcp := detector.NewConn(rawTCP)
	if !errors.Is(detector.CheckConn(metadata), ErrReject) {
		t.Fatal("TCP loopback not rejected")
	}
	if err := tcp.Close(); err != nil {
		t.Fatal(err)
	}
	if !rawTCP.closed || detector.CheckConn(metadata) != nil {
		t.Fatal("TCP close did not release tracking")
	}
	rawUDP := &trackedPacketConn{local: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}}
	udp := detector.NewPacketConn(rawUDP)
	if !errors.Is(detector.CheckPacketConn(metadata), ErrReject) {
		t.Fatal("UDP loopback not rejected")
	}
	if err := udp.Close(); err != nil {
		t.Fatal(err)
	}
	if !rawUDP.closed || detector.CheckPacketConn(metadata) != nil {
		t.Fatal("UDP close did not release tracking")
	}
	disableLoopBackDetector = true
	if NewDetector() != nil {
		t.Fatal("explicit disable ignored")
	}
	var disabled *Detector
	if disabled.CheckConn(metadata) != nil || disabled.CheckPacketConn(metadata) != nil {
		t.Fatal("disabled detector must be no-op")
	}
}
