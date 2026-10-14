package vless

import (
	"bytes"
	"io"
	"testing"
)

func TestStandardAndX365WireBoundaries(t *testing.T) {
	for _, mode := range []string{"standard", "x365"} {
		for _, command := range []string{"tcp", "udp", "mux"} {
			t.Run(mode+"/"+command, func(t *testing.T) {
				id := "00000000-0000-0000-0000-000000000000"
				if mode == "x365" {
					id += "#x365"
				}
				client, err := NewClient(id, nil, false)
				if err != nil {
					t.Fatal(err)
				}
				dst := &DstAddr{Port: 443, AddrType: AtypDomainName, Addr: append([]byte{12}, []byte("example.test")...), UDP: command == "udp", Mux: command == "mux"}
				wire := &juziPureMemoryConn{}
				conn, err := client.StreamConn(wire, dst)
				if err != nil {
					t.Fatal(err)
				}
				payload := []byte("synthetic payload")
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				cmd := byte(CommandTCP)
				if dst.UDP {
					cmd = CommandUDP
				}
				if dst.Mux {
					cmd = CommandMux
				}
				var want []byte
				if mode == "x365" {
					want = append([]byte{'X', '3', '6', '5', 1, cmd}, make([]byte, 16)...)
				} else {
					want = append([]byte{Version}, make([]byte, 16)...)
					want = append(want, 0, cmd)
				}
				if !dst.Mux {
					want = append(want, 1, 187, AtypDomainName)
					want = append(want, dst.Addr...)
				}
				want = append(want, payload...)
				if len(wire.writes) != 1 || !bytes.Equal(wire.writes[0], want) {
					t.Fatalf("wire mismatch for %s/%s", mode, command)
				}
				if _, err := conn.Write([]byte("next")); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(wire.writes[1], []byte("next")) {
					t.Fatal("handshake sent twice")
				}
				if mode == "x365" {
					wire.readChunks = [][]byte{{'X'}, {'3', '6'}, {'5', 1}, payload}
				} else {
					wire.readChunks = [][]byte{{Version}, {2}, {7, 8}, payload}
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("response header leaked into payload")
				}
			})
		}
	}
}

func TestX365RejectsInvalidResponseMagic(t *testing.T) {
	client, err := NewClient("00000000-0000-0000-0000-000000000000#x365", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	wire := &juziPureMemoryConn{readChunks: [][]byte{[]byte("WRONG")}}
	conn, err := client.StreamConn(wire, &DstAddr{Mux: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil || err.Error() != "invalid x365 response header" {
		t.Fatalf("unexpected response result: %v", err)
	}
}
