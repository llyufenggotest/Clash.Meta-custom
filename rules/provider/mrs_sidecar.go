package provider

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

// Sidecars contain a versioned envelope binding the actual parser input and the
// MRS payload by SHA-256. File timestamps cannot establish content identity:
// Fetcher parses downloaded bytes before publishing the raw cache file.
// A single atomic rename publishes the envelope and bitmap together. A crash
// between sidecar and raw publication leaves a mismatch, never a stale match.
// Legacy bare .mrs sidecars are deliberately rejected and must be rebuilt by
// the unconstrained app. Large raw/classical providers still require startup
// admission control; the low-memory rule budget is not a completeness guarantee.
const sidecarMinRules = 5000
const sidecarMagic = "MRS-SC02"
const sidecarHeaderSize = len(sidecarMagic) + 2*sha256.Size

func sidecarPath(vehiclePath string) string { return vehiclePath + ".mrs" }

// loadFromSidecar reads once, so concurrent replacement cannot separate hash
// validation from the payload used to construct the matcher.
func loadFromSidecar(path string, source []byte, behavior P.RuleBehavior) (ruleStrategy, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return loadFromSidecarBytes(buf, source, behavior)
}

func loadFromSidecarBytes(buf, source []byte, behavior P.RuleBehavior) (ruleStrategy, error) {
	if len(buf) < sidecarHeaderSize || string(buf[:len(sidecarMagic)]) != sidecarMagic {
		return nil, fmt.Errorf("unversioned or truncated MRS sidecar; rebuild in app")
	}
	sourceHash := sha256.Sum256(source)
	payload := buf[sidecarHeaderSize:]
	payloadHash := sha256.Sum256(payload)
	if !bytes.Equal(buf[len(sidecarMagic):len(sidecarMagic)+sha256.Size], sourceHash[:]) ||
		!bytes.Equal(buf[len(sidecarMagic)+sha256.Size:sidecarHeaderSize], payloadHash[:]) {
		return nil, fmt.Errorf("MRS sidecar content hash mismatch; rebuild in app")
	}
	return rulesMrsParse(payload, newStrategy(behavior, nil))
}

// writeSidecar binds the bitmap to parser input, NOT the possibly older raw file.
// Failure is a cache miss, never permission to drop rules or ignore a load error.
func writeSidecar(vehiclePath string, source []byte, behavior P.RuleBehavior, strategy ruleStrategy) {
	mrsStrategy, ok := strategy.(mrsRuleStrategy)
	if !ok || strategy.Count() < sidecarMinRules {
		return
	}
	var payload bytes.Buffer
	if err := WriteMrsFromStrategy(&payload, behavior, mrsStrategy); err != nil {
		log.Warnln("[Provider] build mrs sidecar for %s: %v", vehiclePath, err)
		return
	}
	sourceHash := sha256.Sum256(source)
	payloadHash := sha256.Sum256(payload.Bytes())
	var envelope bytes.Buffer
	envelope.WriteString(sidecarMagic)
	envelope.Write(sourceHash[:])
	envelope.Write(payloadHash[:])
	envelope.Write(payload.Bytes())
	path := sidecarPath(vehiclePath)
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		log.Warnln("[Provider] create mrs sidecar %s: %v", path, err)
		return
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(envelope.Bytes())
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		log.Warnln("[Provider] publish mrs sidecar %s: %v", path, err)
		return
	}
	log.Infoln("[Provider] wrote MRS sidecar for %s (%d rules, %d bytes)", vehiclePath, strategy.Count(), envelope.Len())
}
