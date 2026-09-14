package outbound

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func blackstoneFixture(t *testing.T, h *XHttp, plaintext []byte) []byte {
	t.Helper()
	seed := []byte("0123456789abcdef0123456789abcdef")
	key := h.vmessKDF(seed, "CHACHA 20 POLY 1305")
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("fixtureNonce")
	ciphertext := append(append([]byte{}, nonce...), aead.Seal(nil, nonce, plaintext, nil)...)
	seedASCII := []byte(hex.EncodeToString(seed))

	payload := append(append([]byte{}, seedASCII...), ciphertext...)
	raw := make([]byte, 9, 9+len(payload))
	raw[0] = 1
	binary.BigEndian.PutUint32(raw[1:5], 0)
	binary.BigEndian.PutUint32(raw[5:9], uint32(len(seedASCII)))
	return append(raw, payload...)
}

func TestXHTTPRequestEncryptionGolden(t *testing.T) {
	h := &XHttp{}
	const plaintext = `{"X-TOKEN":"offline-token"}`
	const want = "EW8STAwVEwItE3lAOxQPXTwAN0kCJVgMFFJF"
	if got := h.encryptRequestData(plaintext); got != want {
		t.Fatalf("request encryption mismatch\nwant %s\n got %s", want, got)
	}
}

func TestBlackstonePayloadDecryptsFixture(t *testing.T) {
	h := &XHttp{}
	want := []byte(`{"proxies":[{"name":"offline"}]}`)
	got, err := h.decryptBlackstonePayload(blackstoneFixture(t, h, want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("plaintext mismatch\nwant %q\n got %q", want, got)
	}
}

func TestBlackstonePayloadRejectsMalformedInput(t *testing.T) {
	h := &XHttp{}
	valid := blackstoneFixture(t, h, []byte("fixture"))

	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "empty", raw: nil, want: "data too short"},
		{name: "truncated table", raw: []byte{1, 0, 0}, want: "header size error"},
		{name: "missing ciphertext", raw: append([]byte{1, 0, 0, 0, 0, 0, 0, 0, 1}, '0'), want: "ciphertext too short"},
		{name: "tampered ciphertext", raw: append([]byte{}, valid...), want: "message authentication failed"},
	}
	tests[len(tests)-1].raw[len(tests[len(tests)-1].raw)-1] ^= 0xff

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.decryptBlackstonePayload(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}
