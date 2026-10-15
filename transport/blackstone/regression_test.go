package blackstone

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	M "github.com/metacubex/sing/common/metadata"
)

func TestAllCipherBidirectionalTCPAndPacket(t *testing.T) {
	vectors := []struct{ method, key string }{
		{"aes-128-ctr", "5f06b85e1619b2b8b56f7b758a0a310a"},
		{"aes-192-ctr", "5f06b85e1619b2b8b56f7b758a0a310a737fb43703acf936"},
		{"aes-256-ctr", "5f06b85e1619b2b8b56f7b758a0a310a737fb43703acf936c6280204ae5f6506"},
	}
	address := []byte{1, 192, 0, 2, 1, 0, 53}
	for _, v := range vectors {
		t.Run(v.method, func(t *testing.T) {
			client, _ := New(Config{Password: "synthetic:0102", Cipher: v.method})
			key, _ := hex.DecodeString(v.key)
			raw := &memoryConn{input: bytes.NewReader(syntheticServer(key, []byte{0x10, 7}, []byte("answer")))}
			stream := client.StreamConn(raw, address)
			for _, payload := range [][]byte{nil, []byte("up"), []byte("link")} {
				if _, err := stream.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			frame := raw.Bytes()
			block, _ := aes.NewCipher(key)
			plain := make([]byte, len(frame)-163)
			cipher.NewCTR(block, frame[147:163]).XORKeyStream(plain, frame[163:])
			if !bytes.Equal(plain, append(append([]byte(nil), address...), []byte("uplink")...)) {
				t.Fatal("TCP uplink mismatch")
			}
			var received []byte
			for range 6 {
				var one [1]byte
				if _, err := io.ReadFull(stream, one[:]); err != nil {
					t.Fatal(err)
				}
				received = append(received, one[0])
			}
			if string(received) != "answer" {
				t.Fatal("TCP downlink mismatch")
			}
			// New wrappers capture published H; old wrappers retain old auth.
			nextRaw := &memoryConn{}
			next := client.StreamConn(nextRaw, address)
			if _, err := next.Write(nil); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(nextRaw.Bytes()[144:148], []byte{2, 0x10, 7, 16}) {
				t.Fatal("next TCP did not emit updated auth")
			}
			if !bytes.Equal(stream.auth, []byte{1, 2}) {
				t.Fatal("existing TCP auth mutated")
			}
			packetRaw := &memoryPacket{}
			pc := client.PacketConn(packetRaw, M.ParseSocksaddr("127.0.0.1:1"))
			if _, err := pc.WriteTo([]byte("query"), M.ParseSocksaddr("192.0.2.1:53")); err != nil {
				t.Fatal(err)
			}
			packet := packetRaw.writes[0]
			decoded := make([]byte, len(packet)-164)
			cipher.NewCTR(block, packet[148:164]).XORKeyStream(decoded, packet[164:])
			if !bytes.Equal(decoded, append(append([]byte(nil), address...), []byte("query")...)) {
				t.Fatal("UDP uplink mismatch")
			}
			packetRaw.read = syntheticServer(key, nil, append(append([]byte(nil), address...), []byte("reply")...))
			packetRaw.actual = len(packetRaw.read)
			p := make([]byte, 5)
			if n, source, err := pc.ReadFrom(p); err != nil || n != 5 || string(p) != "reply" || source.String() != "192.0.2.1:53" {
				t.Fatal("UDP downlink mismatch", n, source, err)
			}
		})
	}
}

func TestConcurrentAuthPublicationSnapshots(t *testing.T) {
	client, _ := New(Config{Password: "synthetic:0102"})
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			for range 32 {
				client.publish([]byte{1, byte(i)})
				stream := client.StreamConn(&memoryConn{}, nil)
				if len(stream.auth) != 2 || stream.auth[0] != 1 {
					t.Error("torn auth snapshot")
				}
			}
		})
	}
	wg.Wait()
}

func TestStreamAndUOTDeadlinesAndClose(t *testing.T) {
	for _, packet := range []bool{false, true} {
		t.Run(map[bool]string{false: "TCP", true: "UOT"}[packet], func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			client, _ := New(Config{Password: "synthetic:0102"})
			stream := client.StreamConn(a, nil)
			stream.SetReadDeadline(time.Now().Add(15 * time.Millisecond))
			if packet {
				pc, _ := NewUOT(stream, 2, M.ParseSocksaddr("192.0.2.1:53"))
				if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal("read deadline lost", err)
				}
				pc.Close()
			} else {
				if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal("read deadline lost", err)
				}
				stream.Close()
			}
			if _, err := b.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal("close not forwarded", err)
			}
		})
	}
}
