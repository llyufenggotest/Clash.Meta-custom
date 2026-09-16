package outbound

import (
	"encoding/base64"
	"testing"
)

func TestXHTTPRejectsMalformedAPIEnvelope(t *testing.T) {
	x := &XHttp{}
	cases := []string{
		base64.StdEncoding.EncodeToString([]byte(`{}`)),
		base64.StdEncoding.EncodeToString([]byte(`{"data":"bad"}`)),
		base64.StdEncoding.EncodeToString([]byte(`{"data":{"smart":1}}`)),
	}
	for _, input := range cases {
		if _, err := x.processApiData(input); err == nil {
			t.Fatalf("processApiData(%q) succeeded", input)
		}
	}
}

func TestXHTTPAPIClientVerifiesTLS(t *testing.T) {
	transport := xhttpAPITransport(nil)
	if transport.TLSClientConfig == nil {
		t.Fatal("missing TLS client config")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("XHTTP API TLS verification is disabled")
	}
	if transport.TLSClientConfig.ServerName != xhttpAPIHost {
		t.Fatalf("unexpected TLS server name %q", transport.TLSClientConfig.ServerName)
	}
}
