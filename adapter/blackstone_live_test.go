package adapter

import (
	"context"
	"crypto/tls"
	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Opt-in only; subscription secrets remain in memory and are never logged.
func TestBlackstoneLiveSelectedYAML(t *testing.T) {
	path := os.Getenv("BLACKSTONE_LIVE_YAML")
	if path == "" {
		t.Skip("authorized subscription not supplied")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("private YAML unavailable")
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(b, &doc) != nil {
		t.Fatal("invalid subscription YAML")
	}
	var p C.Proxy
	for _, m := range doc.Proxies {
		if m["type"] == "Blackstone" {
			p, err = ParseProxy(m)
			break
		}
	}
	if err != nil || p == nil {
		t.Fatal("selected subscription parser failed")
	}
	t.Log("selected YAML parsed; device pair retained in memory")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var n uint16
		if port == "443" {
			n = 443
		} else {
			return nil, io.ErrUnexpectedEOF
		}
		return p.DialContext(ctx, &C.Metadata{Host: host, DstPort: n, Type: C.HTTP, NetWork: C.TCP})
	}, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, target := range []struct {
		url    string
		status int
	}{{"https://www.google.com/generate_204", 204}, {"https://www.cloudflare.com/cdn-cgi/trace", 200}} {
		req, _ := http.NewRequestWithContext(ctx, "GET", target.url, nil)
		resp, err := client.Do(req)
		if err != nil {
			// Print only the fixed status classification, never request/header values.
			if status := regexp.MustCompile(`api returned status: [0-9]{3}`).FindString(err.Error()); status != "" {
				t.Log(status)
			}
			if strings.Contains(err.Error(), "api request failed") {
				t.Log("control request transport failure")
			}
			if strings.Contains(err.Error(), "ciphertext") {
				t.Log("control inner ciphertext rejected")
			}
			if strings.Contains(err.Error(), "invalid xhttp password") {
				t.Log("dynamic node password format rejected")
			}
			if strings.Contains(err.Error(), "api returned status: 401") {
				t.Log("control HTTP 401; device/token admission blocked")
			}
			if strings.Contains(err.Error(), "api returned status: 403") {
				t.Log("control HTTP 403; admission blocked")
			}
			if strings.Contains(err.Error(), "api data field must be a non-empty string") {
				t.Log("control response missing usable config data; business/device admission not successful")
			}
			if strings.Contains(err.Error(), "decode api envelope") {
				t.Log("control response envelope not accepted")
			}
			if strings.Contains(err.Error(), "no target node matched") {
				t.Log("control config accepted but selected node name not matched")
			}
			if strings.Contains(err.Error(), "all dynamic nodes failed") {
				t.Log("matched config TCP ping race failed")
			}
			t.Fatalf("BLOCKED actual Go adapter request %s (control/device/transport refused; sensitive error suppressed)", target.url)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		t.Logf("actual Go adapter %s status=%d received_bytes=%d", target.url, resp.StatusCode, n)
		if err != nil || resp.StatusCode != target.status {
			t.Fatal("unexpected data-plane result")
		}
	}
}
