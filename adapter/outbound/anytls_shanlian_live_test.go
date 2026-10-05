package outbound

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestLiveShanlianAnyTLS(t *testing.T) {
	credential := os.Getenv("MIHOMO_TEST_SHANLIAN_CREDENTIAL")
	if credential == "" {
		t.Skip("MIHOMO_TEST_SHANLIAN_CREDENTIAL is unset")
	}
	proxy, err := NewAnyTLS(AnyTLSOption{
		Name:              "shanlian-live",
		Server:            "103.208.85.5",
		Port:              443,
		Password:          credential,
		SNI:               "v-thumb.byteimg.com",
		ClientFingerprint: "chrome",
		SkipCertVerify:    true,
		UDP:               true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 64)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("Shanlian AnyTLS returned no application data")
	}
}
