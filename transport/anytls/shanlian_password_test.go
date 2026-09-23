package anytls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const shanlianFixture = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestShanlianPasswordUsesDirectAuthenticationBytes(t *testing.T) {
	got, err := decodeClientPassword(shanlianFixture + "#sl")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(shanlianFixture)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestShanlianPasswordMarkerIsCaseInsensitive(t *testing.T) {
	got, err := decodeClientPassword(shanlianFixture + "#SL")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(shanlianFixture)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestInvalidShanlianPasswordFailsClosed(t *testing.T) {
	for _, password := range []string{"short#sl", strings.Repeat("z", 64) + "#sl"} {
		if _, err := decodeClientPassword(password); err == nil {
			t.Fatalf("accepted invalid Shanlian password %q", password)
		}
	}
}

func TestOrdinaryAnyTLSPasswordUsesSHA256(t *testing.T) {
	password := "ordinary-password"
	got, err := decodeClientPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(password))
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestNearMarkerRemainsOrdinaryPassword(t *testing.T) {
	password := shanlianFixture + "#sl-extra"
	got, err := decodeClientPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(password))
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("got %x, want %x", got, want)
	}
}
