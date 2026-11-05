package outbound

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
)

// A single proxy write puts target bytes into ReadResponse's reader buffer.
// No external proxy, DNS lookup or private endpoint is used.
func TestHTTPConnectPreservesBufferedTargetBytes(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	deadline := time.Now().Add(2 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)
	serverResult := make(chan error, 1)
	go func() {
		_, err := http.ReadRequest(bufio.NewReader(server))
		if err == nil {
			_, err = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\ntarget-prefix")
		}
		_ = server.Close()
		serverResult <- err
	}()
	proxy, err := NewHttp(HttpOption{Name: "buffer-regression", Server: "127.0.0.1", Port: 1})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := proxy.StreamConnContext(context.Background(), client, &C.Metadata{Host: "target.invalid", DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("target-prefix"))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatalf("CONNECT target bytes were discarded: %v", err)
	}
	if string(got) != "target-prefix" {
		t.Fatalf("target payload = %q", got)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
