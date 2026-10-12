package adapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

type blackstoneWireCounter struct {
	net.Conn
	read, written *atomic.Int64
}

func (c *blackstoneWireCounter) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.read.Add(int64(n))
	return n, e
}
func (c *blackstoneWireCounter) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.written.Add(int64(n))
	return n, e
}

func blackstoneSafeError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "class=canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "class=deadline"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "class=network_timeout"
	}
	text := err.Error()
	if s := regexp.MustCompile(`api returned status: [0-9]{3}`).FindString(text); s != "" {
		return s
	}
	if s := regexp.MustCompile(`control response http=[0-9]{3} business=[0-9-]+ message=[a-z_]+`).FindString(text); s != "" {
		return s
	}
	for _, stage := range []string{"decrypted data field is missing", "api returned no valid nodes", "header size error", "data too short", "chacha20poly1305: message authentication failed", "illegal base64 data", "EOF", "connection reset", "api request failed", "decode api envelope", "decode smart payload", "decode smart config", "smart field", "api data field", "ciphertext", "no target node matched", "all dynamic nodes failed", "invalid xhttp password", "IV offset padding", "live wire instrumentation"} {
		if strings.Contains(text, stage) {
			return fmt.Sprintf("stage=%s class=%T", stage, err)
		}
	}
	return fmt.Sprintf("class=%T detail=redacted", err)
}
func TestBlackstoneNoSecretsFixtureAssertion(t *testing.T) {
	secrets := []string{"fixture-token", "fixture-device-id", "fixture-uuid", "fixture-certificate", "192.0.2.44", "fixture-password"}
	for _, prefix := range []string{"api request failed", "no target node matched", "control response http=200 business=401 message=unauthorized", "arbitrary"} {
		safe := blackstoneSafeError(errors.New(prefix + ": " + strings.Join(secrets, " ")))
		for _, secret := range secrets {
			if strings.Contains(safe, secret) {
				t.Fatal("diagnostic leaked fixture secret")
			}
		}
	}
}
func TestBlackstoneVLESSXHTTPIsolation(t *testing.T) {
	p, e := ParseProxy(map[string]any{"type": "vless", "name": "synthetic", "server": "127.0.0.1", "port": 443, "uuid": "00000000-0000-0000-0000-000000000001", "network": "xhttp", "xhttp-opts": map[string]any{"path": "/synthetic", "mode": "auto"}})
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	if p.Type().String() != "Vless" {
		t.Fatal("ordinary VLESS xhttp dispatched to Blackstone")
	}
}
