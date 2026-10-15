package outbound

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestBlackstoneSelectionDevicePairBoundary(t *testing.T) {
	for _, o := range []XHttpOption{{}, {DeviceID: "synthetic"}, {DeviceName: "synthetic"}, {DeviceID: "synthetic", DeviceName: "synthetic"}} {
		name := "legacy"
		if o.DeviceID != "" {
			name += "-id"
		}
		if o.DeviceName != "" {
			name += "-name"
		}
		t.Run(name, func(t *testing.T) {
			h, _ := NewXHttp(o)
			plain := "proxies:\n - {name: synthetic, type: xhttp, server: 127.0.0.1, port: 4321, password: 'synthetic:00'}\n"
			envelope := fixtureBlackstoneEnvelope(t, h, plain)
			fixtureBlackstoneClient(t, func(*http.Request) (*http.Response, error) {
				return blackstoneResponse(`{"data":"` + envelope + `"}`), nil
			})
			got, err := h.fetchDynamicConfig(context.Background(), "synthetic", "synthetic")
			if o.DeviceID != "" && o.DeviceName != "" {
				if err == nil || got != nil || !strings.Contains(err.Error(), "stage=node-selection") {
					t.Fatal("canonical response missing mode/rules unexpectedly repaired")
				}
			} else if err != nil || len(got) != 1 {
				t.Fatal("legacy/partial device boundary changed")
			}
		})
	}
}
