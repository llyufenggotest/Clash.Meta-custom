package outbound

import "testing"

func TestPrepareX365XHTTPHeadersAddsOfficialUserAgent(t *testing.T) {
	got := prepareX365XHTTPHeaders(map[string]string{"Host": "example.com"}, true)
	if got["User-Agent"] != x365UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got["User-Agent"], x365UserAgent)
	}
}

func TestPrepareX365XHTTPHeadersPreservesExplicitUserAgentCaseInsensitively(t *testing.T) {
	got := prepareX365XHTTPHeaders(map[string]string{"user-agent": "custom"}, true)
	if got["user-agent"] != "custom" || len(got) != 1 {
		t.Fatalf("headers = %#v, want explicit user-agent only", got)
	}
}

func TestPrepareX365XHTTPHeadersDoesNotChangeOrdinaryXHTTP(t *testing.T) {
	headers := map[string]string{"Host": "example.com"}
	got := prepareX365XHTTPHeaders(headers, false)
	if len(got) != len(headers) || got["User-Agent"] != "" {
		t.Fatalf("headers = %#v, ordinary XHTTP was changed", got)
	}
	if got["Host"] != "example.com" {
		t.Fatal("ordinary XHTTP headers changed")
	}
}
