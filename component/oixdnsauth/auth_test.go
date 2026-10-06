package oixdnsauth

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestSignedHostnameMatchesEd25519Vector(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	got, err := Host("A.example.test.", base64.StdEncoding.EncodeToString(seed), []string{"example.test"}, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(got, ".")
	if len(parts) != 5 || len(parts[0]) != 52 || len(parts[1]) != 52 {
		t.Fatalf("bad labels: %q", got)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	a, e1 := enc.DecodeString(strings.ToUpper(parts[0]))
	b, e2 := enc.DecodeString(strings.ToUpper(parts[1]))
	if e1 != nil || e2 != nil || !ed25519.Verify(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), []byte("a.example.test|5666666"), append(a, b...)) {
		t.Fatal("signature/message mismatch")
	}
}

func TestUnmanagedHostsAreBytePreserved(t *testing.T) {
	for _, host := range []string{"", "127.0.0.1", "2001:db8::1", "UPPER.EXAMPLE.", "notcloud-nodes.com", "cloud-nodes.com.evil.test", "x.cloud-nodes.com:443"} {
		got, err := Host(host, "", []string{"cloud-nodes.com"}, 0)
		if err != nil || got != host {
			t.Fatalf("unmanaged host modified: %q", host)
		}
	}
}

func TestManagedHostRequiresPrivateSeed(t *testing.T) {
	for _, seed := range []string{"", "invalid", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		got, err := Host("cloud-nodes.com", seed, []string{"cloud-nodes.com"}, 0)
		if err == nil || got != "" {
			t.Fatal("invalid seed did not fail closed")
		}
		if seed != "" && strings.Contains(err.Error(), seed) {
			t.Fatal("error exposes seed")
		}
	}
}

func TestTimeBucketAndNormalization(t *testing.T) {
	seed := base64.StdEncoding.EncodeToString(make([]byte, 32))
	a, _ := Host("X.example.test.", seed, []string{"example.test"}, 299)
	b, _ := Host("x.example.test", seed, []string{"example.test"}, 0)
	c, _ := Host("x.example.test", seed, []string{"example.test"}, 300)
	d, _ := Host("x.example.test", seed, []string{"example.test"}, -299)
	if a != b || a != d || a == c {
		t.Fatal("time-bucket/normalization mismatch")
	}
}

// Optional parity input stays in the local process environment, not source.
func TestOfficialSampleParity(t *testing.T) {
	seed := os.Getenv("OIX_TEST_DNS_SEED")
	if seed == "" {
		t.Skip("private official sample input not supplied")
	}
	host := os.Getenv("OIX_TEST_HOST")
	expected := os.Getenv("OIX_TEST_QUERY")
	timestamp, err := strconv.ParseInt(os.Getenv("OIX_TEST_TIMESTAMP"), 10, 64)
	if err != nil {
		t.Fatal("invalid test timestamp")
	}
	got, err := Host(host, seed, []string{"cloud-nodes.com"}, timestamp)
	if err != nil || got != expected {
		t.Fatal("official sample parity mismatch")
	}
}
