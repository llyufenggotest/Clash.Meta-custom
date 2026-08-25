package oppa

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

func TestPacketConnWriteTo(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewPacketConn(client)
	destination := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("8.8.8.8:53"))
	payload := []byte{1, 2, 3, 4}

	done := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo(payload, destination)
		done <- err
	}()

	source, gotDestination, gotPayload, err := DecodeUDPFrame(server)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if source.IP != netip.IPv4Unspecified() || source.Port != 0 {
		t.Fatalf("unexpected source: %v", source)
	}
	if gotDestination.IP != netip.MustParseAddr("8.8.8.8") || gotDestination.Port != 53 {
		t.Fatalf("unexpected destination: %v", gotDestination)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch: %x", gotPayload)
	}
}

func TestPacketConnReadFrom(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	pc := NewPacketConn(client)
	source := Address{IP: netip.IPv4Unspecified()}
	destination := Address{Domain: "dns.example", Port: 53}
	payload := []byte{9, 8, 7}
	frame, err := EncodeUDPFrame(source, destination, payload)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = server.Write(frame) }()

	buffer := make([]byte, 32)
	n, address, err := pc.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("payload mismatch: %x", buffer[:n])
	}
	if address.String() != "dns.example:53" {
		t.Fatalf("unexpected address: %s", address)
	}
}
