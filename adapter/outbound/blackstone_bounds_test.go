package outbound

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestBlackstoneChunkRangesRejectedBeforeIteration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		start, end uint32
	}{{"reversed", 2, 1}, {"outside", 0, 2}, {"start-outside", 2, 2}, {"max-uint32", 0, ^uint32(0)}} {
		t.Run(tc.name, func(t *testing.T) {
			raw := make([]byte, 10)
			raw[0] = 1
			binary.BigEndian.PutUint32(raw[1:5], tc.start)
			binary.BigEndian.PutUint32(raw[5:9], tc.end)
			envelope := blackstoneOuterPayload(raw)
			h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) { return blackstoneResponse(envelope), nil })
			_, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
			if err == nil || !strings.Contains(blackstoneTestUnderlyingText(err), "chunk range") {
				t.Fatalf("invalid range not rejected at chunk boundary: %v", err)
			}
		})
	}
}

func blackstoneOuterPayload(raw []byte) string {
	// A real outer envelope feeding the production decrypt path.
	outer, _ := json.Marshal(map[string]any{"data": map[string]string{"smart": base64.StdEncoding.EncodeToString(raw)}})
	for i := range outer {
		outer[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	body, _ := json.Marshal(map[string]string{"data": base64.StdEncoding.EncodeToString(outer)})
	return string(body)
}

func blackstoneResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestBlackstoneValidChunkBoundaryWirePreserved(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{})
	// Same legacy cipher construction, with an unused empty range [len,len].
	outerB64 := fixtureBlackstoneEnvelope(t, h, "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 443, password: 'synthetic:00'}\n")
	outer, _ := base64.StdEncoding.DecodeString(outerB64)
	for i := range outer {
		outer[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
	}
	var obj map[string]any
	_ = json.Unmarshal(outer, &obj)
	data := obj["data"].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(data["smart"].(string))
	payloadLen := uint32(len(raw) - 9)
	expanded := make([]byte, 17)
	expanded[0] = 2
	copy(expanded[1:9], raw[1:9])
	binary.BigEndian.PutUint32(expanded[9:13], payloadLen)
	binary.BigEndian.PutUint32(expanded[13:17], payloadLen)
	expanded = append(expanded, raw[9:]...)
	for _, payload := range [][]byte{raw, expanded} {
		data["smart"] = base64.StdEncoding.EncodeToString(payload)
		b, _ := json.Marshal(obj)
		for i := range b {
			b[i] ^= xhttpPrivKey[i%len(xhttpPrivKey)]
		}
		configs, err := h.processApiData(base64.StdEncoding.EncodeToString(b))
		if err != nil || len(configs) != 1 || configs[0].Server != "127.0.0.1" || configs[0].Port != "443" {
			t.Fatal("valid inclusive bounds changed cipher wire")
		}
	}
}

func TestBlackstoneResponseBodyLimits(t *testing.T) {
	for _, size := range []int{xhttpMaxAPIResponseBytes, xhttpMaxAPIResponseBytes + 1} {
		h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
		fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
			return blackstoneResponse(strings.Repeat(" ", size-len(`{"code":401}`)) + `{"code":401}`), nil
		})
		_, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
		if err == nil {
			t.Fatal("missing envelope accepted")
		}
		if strings.Contains(blackstoneTestUnderlyingText(err), "exceeds") != (size > xhttpMaxAPIResponseBytes) {
			t.Fatal("incorrect HTTP body limit boundary")
		}
	}
}

func TestBlackstoneGzipLimitsAndTruncation(t *testing.T) {
	for _, size := range []int{xhttpMaxPlaintextBytes, xhttpMaxPlaintextBytes + 1} {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write(bytes.Repeat([]byte{'x'}, size))
		w.Close()
		got, err := gunzipLimited(b.Bytes())
		if size == xhttpMaxPlaintextBytes {
			if err != nil || len(got) != size {
				t.Fatal("exact gzip boundary rejected")
			}
		} else if err == nil {
			t.Fatal("gzip bomb accepted")
		}
		if _, err := gunzipLimited(b.Bytes()[:b.Len()-4]); err == nil {
			t.Fatal("truncated gzip accepted")
		}
	}
}

type blackstoneReadErrorBody struct{}

func (blackstoneReadErrorBody) Read([]byte) (int, error) {
	return 0, errors.New("synthetic read failure")
}
func (blackstoneReadErrorBody) Close() error { return nil }
func TestBlackstoneBodyReadFailure(t *testing.T) {
	h, _ := NewXHttp(XHttpOption{DeviceID: "synthetic", DeviceName: "synthetic"})
	fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: blackstoneReadErrorBody{}}, nil
	})
	if _, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic"); err == nil {
		t.Fatal("body read failure ignored")
	}
}
