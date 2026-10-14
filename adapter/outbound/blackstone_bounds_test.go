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
			if err == nil || !strings.Contains(err.Error(), "chunk range") {
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
		if strings.Contains(err.Error(), "exceeds") != (size > xhttpMaxAPIResponseBytes) {
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
