package tls

import (
	"testing"

	utls "github.com/metacubex/utls"
)

func TestDisableRenegotiationForECH(t *testing.T) {
	config := &Config{ServerName: "example.com"}
	conn := UClient(nil, config, utls.HelloChrome_Auto)
	if err := DisableRenegotiationForECH(conn); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, extension := range conn.Extensions {
		if renegotiation, ok := extension.(*utls.RenegotiationInfoExtension); ok {
			found = true
			if renegotiation.Renegotiation != utls.RenegotiateNever {
				t.Fatalf("renegotiation=%v", renegotiation.Renegotiation)
			}
		}
	}
	if !found {
		t.Fatal("Chrome ClientHello lacks renegotiation extension")
	}
}
