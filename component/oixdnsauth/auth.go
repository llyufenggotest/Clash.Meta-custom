// Package oixdnsauth implements authenticated managed DNS names used by Oix.
// Secrets must be supplied privately at build time or through runtime settings.
package oixdnsauth

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// BuildSeed is intentionally empty in tracked source. Release builds inject it
// using an ignored private init file; never commit the credential or put it in
// linker flags (Go records flags in binary build metadata).
var BuildSeed string

func Host(host, seed string, suffixes []string, unixSeconds int64) (string, error) {
	normalized := strings.ToLower(strings.TrimSuffix(host, "."))
	matched := false
	for _, suffix := range suffixes {
		if normalized == suffix || strings.HasSuffix(normalized, "."+suffix) {
			matched = true
			break
		}
	}
	if host == "" || !matched {
		return host, nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seed))
	if err != nil || len(raw) != ed25519.SeedSize {
		return "", errors.New("Oix DNS-Auth requires a valid private 32-byte seed")
	}
	message := []byte(normalized + "|" + strconv.FormatInt(unixSeconds/300, 10))
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(raw), message)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(sig[:32])) + "." + strings.ToLower(enc.EncodeToString(sig[32:])) + "." + normalized, nil
}
