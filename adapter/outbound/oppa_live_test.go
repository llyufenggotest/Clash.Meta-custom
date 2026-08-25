package outbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func liveOppaOption(t *testing.T) OppaOption {
	t.Helper()
	if os.Getenv("OPPA_LIVE") != "1" {
		t.Skip("set OPPA_LIVE=1 with OPPA_SERVER and OPPA_PASSWORD")
	}
	server := os.Getenv("OPPA_SERVER")
	password := os.Getenv("OPPA_PASSWORD")
	if server == "" || password == "" {
		t.Fatal("missing Oppa live test environment")
	}
	host, portText, err := net.SplitHostPort(server)
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatal(err)
	}
	return OppaOption{
		Name:           "Oppa live",
		Server:         host,
		Port:           port,
		Password:       password,
		SNI:            os.Getenv("OPPA_SNI"),
		SkipCertVerify: false,
		NameCertVerify: os.Getenv("OPPA_SNI"),
		UDP:            true,
	}
}

func TestLiveOppaHTTP(t *testing.T) {
	proxy, err := NewOppa(liveOppaOption(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("unexpected HTTP status: %s", strings.TrimSpace(status))
	}
}

func TestLiveOppaUDP(t *testing.T) {
	proxy, err := NewOppa(liveOppaOption(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("8.8.8.8"), DstPort: 53}
	conn, err := proxy.ListenPacketContext(ctx, metadata)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	query := dnsQuery(0x4f50, "example.com")
	if _, err = conn.WriteTo(query, net.UDPAddrFromAddrPort(metadata.AddrPort())); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2048)
	n, _, err := conn.ReadFrom(response)
	if err != nil {
		t.Fatal(err)
	}
	if n < 12 || binary.BigEndian.Uint16(response[:2]) != 0x4f50 || response[3]&0x80 == 0 {
		t.Fatalf("invalid DNS response (%d bytes)", n)
	}
}

func dnsQuery(id uint16, domain string) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range strings.Split(domain, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	return packet
}
