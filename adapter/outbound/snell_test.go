package outbound

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/ech"
)

func TestSnellStandardV4ReuseDefaultsOff(t *testing.T) {
	adapter, err := NewSnell(SnellOption{
		Name: "standard", Server: "127.0.0.1", Port: 443, Psk: "ordinary-secret", Version: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if adapter.reuse {
		t.Fatal("standard Snell v4 unexpectedly enabled reuse")
	}
}

func TestSnellOIXV4ReuseDefaultsOn(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewSnell(SnellOption{
		Name: "oix", Server: "127.0.0.1", Port: 443, Psk: "synthetic-secret#oix", Version: 4,
		ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": echConfig},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if !adapter.reuse {
		t.Fatal("OIX Snell v4 did not enable default reuse")
	}
}

func TestSnellECHTLSRejectsUnsupportedCAFile(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "oix", Server: "127.0.0.1", Port: 443, Psk: "synthetic-secret#oix", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "ech-config": echConfig, "ca-file": "synthetic-ca.pem",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "ca-file is not supported") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellOIXSuffixIsExactAndStripped(t *testing.T) {
	clean, enabled := splitSnellOIXPSK("synthetic-secret#oix")
	if !enabled || clean != "synthetic-secret" {
		t.Fatalf("splitSnellOIXPSK() = (%q, %v)", clean, enabled)
	}
	for _, psk := range []string{"synthetic-secret", "synthetic-secret#OIX", "#oix-middle-secret"} {
		clean, enabled = splitSnellOIXPSK(psk)
		if enabled || clean != psk {
			t.Fatalf("ordinary psk %q changed to (%q, %v)", psk, clean, enabled)
		}
	}
}

func TestSnellECHTLSRequiresOIXSuffix(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "ordinary-secret", Version: 4,
		ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": echConfig},
	})
	if err == nil || !strings.Contains(err.Error(), "requires psk suffix #oix") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellOIXStoresStrippedPSK(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "synthetic-secret#oix", Version: 4,
		ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": echConfig},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if !adapter.oix || string(adapter.psk) != "synthetic-secret" || adapter.option.Psk != "synthetic-secret" {
		t.Fatalf("oix=%v wirePSK=%q optionPSK=%q", adapter.oix, adapter.psk, adapter.option.Psk)
	}
}

func TestSnellECHTLSUsesRawTLSWithoutPath(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := NewSnell(SnellOption{
		Name:    "snell",
		Server:  "origin.example.com",
		Port:    443,
		Psk:     "synthetic-secret#oix",
		Version: 4,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatalf("NewSnell() error = %v", err)
	}
	defer adapter.Close()

	if adapter.echTLS == nil || adapter.echTLS.ECH == nil {
		t.Fatal("ECH TLS config was not initialized")
	}
	if len(adapter.echTLS.NextProtos) != 1 || adapter.echTLS.NextProtos[0] != snellECHTLSALPN {
		t.Fatalf("NextProtos = %q, want [%q]", adapter.echTLS.NextProtos, snellECHTLSALPN)
	}
}

func TestSnellECHTLSRejectsSkippedCertificateVerification(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "synthetic-secret#oix", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "ech-config": echConfig, "skip-cert-verify": true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "requires certificate verification") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellECHTLSLegacyFallbackMustBeExplicit(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "synthetic-secret#oix", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "alpn": snellECHTLSALPN,
			"identity-version": 2, "legacy-fallback": true, "ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if got := adapter.echTLS.NextProtos; len(got) != 2 || got[0] != snellECHTLSALPN || got[1] != snellECHTLSLegacyALPN {
		t.Fatalf("NextProtos = %q", got)
	}
}

func TestSnellECHTLSRejectsConflictingALPNAlias(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "synthetic-secret#oix", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "alpn": snellECHTLSALPN,
			"protocol": "other/1", "ech-config": echConfig,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "values conflict") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellECHTLSAcceptsPreviousProtocolAlias(t *testing.T) {
	got, err := resolveSnellECHTLSALPN("", snellECHTLSPreviousALPN)
	if err != nil || got != snellECHTLSALPN {
		t.Fatalf("resolveSnellECHTLSALPN() = (%q, %v)", got, err)
	}
}

func TestSnellRejectsAnyTLSObfs(t *testing.T) {
	_, err := NewSnell(SnellOption{
		Name:   "snell",
		Server: "127.0.0.1",
		Port:   443,
		Psk:    "password",
		ObfsOpts: map[string]any{
			"mode":     "anytls",
			"password": "outer-password",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "obfs mode error: anytls") {
		t.Fatalf("NewSnell() error = %v, want unsupported anytls obfs", err)
	}
}

func TestSnellRejectsDisabledIdentityForECHTLS(t *testing.T) {
	_, err := NewSnell(SnellOption{
		Name:               "snell",
		Server:             "127.0.0.1",
		Port:               443,
		Psk:                "synthetic-secret#oix",
		Version:            4,
		IdentityConfigured: true,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"path":       "/snell",
			"ech-config": "invalid",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "identity cannot be disabled") {
		t.Fatalf("NewSnell() error = %v, want disabled identity error", err)
	}
}
