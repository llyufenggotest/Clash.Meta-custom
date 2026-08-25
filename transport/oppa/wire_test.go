package oppa

import (
	"bytes"
	"net/netip"
	"testing"
)

const syntheticToken = "0123456789abcdef0123456789abcdef"

func TestTCPHeaderIPv4(t *testing.T) {
	dst := Address{IP: netip.MustParseAddr("8.8.8.8"), Port: 853}
	got, err := BuildTCPHeader(syntheticToken, dst)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(syntheticToken), []byte{0x01, 0x01, 8, 8, 8, 8, 0x03, 0x55}...)
	if !bytes.Equal(got, want) {
		t.Fatalf("TCP IPv4 header mismatch\nwant %x\n got %x", want, got)
	}
}

func TestTCPHeaderDomain(t *testing.T) {
	dst := Address{Domain: "mtalk.google.com", Port: 5228}
	got, err := BuildTCPHeader(syntheticToken, dst)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(syntheticToken), append([]byte{0x01, 0x03, 0x10}, append([]byte("mtalk.google.com"), 0x14, 0x6c)...)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("TCP domain header mismatch\nwant %x\n got %x", want, got)
	}
}

func TestVariableTokenLengthIsPreserved(t *testing.T) {
	got, err := BuildSessionHeader("future-token", CommandTCP)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "future-token\x01" {
		t.Fatalf("token was changed: %x", got)
	}
	if _, err := BuildSessionHeader("", CommandTCP); err == nil {
		t.Fatal("empty token must be rejected")
	}
}

func TestUDPFrameRoundTrip(t *testing.T) {
	source := Address{IP: netip.IPv4Unspecified(), Port: 0}
	destination := Address{IP: netip.MustParseAddr("8.8.8.8"), Port: 53}
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	frame, err := EncodeUDPFrame(source, destination, payload)
	if err != nil {
		t.Fatal(err)
	}
	gotSource, gotDestination, gotPayload, err := DecodeUDPFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if gotSource != source || gotDestination != destination || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("UDP round trip mismatch: source=%v destination=%v payload=%x", gotSource, gotDestination, gotPayload)
	}
}

func TestUDPFrameRejectsTruncation(t *testing.T) {
	if _, _, _, err := DecodeUDPFrame(bytes.NewReader([]byte{0, 5, 1, 2})); err == nil {
		t.Fatal("truncated frame must fail")
	}
}
