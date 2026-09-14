package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/metacubex/mihomo/common/structure"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/rules/common"
)

// PreparedRuleProvider is the immutable result of preparing one file-backed
// rule provider. Digest is identical to the digest used by extension readiness.
type PreparedRuleProvider struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Sidecar  string `json:"sidecar"`
	Behavior string `json:"behavior"`
	Format   string `json:"format"`
	Count    int    `json:"count"`
	Digest   string `json:"digest"`
}

// PrepareRuleProvider parses one provider definition against caller-selected
// immutable sourcePath and publishes a content-bound MRS-SC03 sidecar. It does
// not construct a Fetcher/provider, bind the tunnel, emit updates, start a file
// watcher, or start an HTTP pull loop.
func PrepareRuleProvider(name string, mapping map[string]any, sourcePath string, parse common.ParseRuleFunc) (PreparedRuleProvider, error) {
	if name == "" {
		return PreparedRuleProvider{}, fmt.Errorf("provider name is empty")
	}
	if sourcePath == "" || !filepath.IsAbs(sourcePath) {
		return PreparedRuleProvider{}, fmt.Errorf("provider target path must be absolute")
	}

	schema := &ruleProviderSchema{}
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	if err := decoder.Decode(mapping, schema); err != nil {
		return PreparedRuleProvider{}, err
	}
	behavior, err := P.ParseBehavior(schema.Behavior)
	if err != nil {
		return PreparedRuleProvider{}, err
	}
	format, err := P.ParseRuleFormat(schema.Format)
	if err != nil {
		return PreparedRuleProvider{}, err
	}
	if behavior == P.Classical {
		return PreparedRuleProvider{}, fmt.Errorf("classical provider has no safe MRS representation")
	}

	raw, err := os.ReadFile(sourcePath)
	if err != nil {
		return PreparedRuleProvider{}, err
	}
	sidecar := sidecarPath(sourcePath)
	if cached, readErr := os.ReadFile(sidecar); readErr == nil {
		if strategy, loadErr := loadFromSidecarBytes(cached, raw, behavior, format); loadErr == nil {
			digest := extensionReadyDigest(behavior, format, strategy.Count(), raw, cached)
			return PreparedRuleProvider{
				Name: name, Path: sourcePath, Sidecar: sidecar,
				Behavior: behavior.String(), Format: format.String(),
				Count: strategy.Count(), Digest: digest,
			}, nil
		}
	}
	strategy, err := rulesParse(raw, newStrategy(behavior, parse), format)
	if err != nil {
		return PreparedRuleProvider{}, err
	}
	mrsStrategy, ok := strategy.(mrsRuleStrategy)
	if !ok {
		return PreparedRuleProvider{}, fmt.Errorf("%s provider has no MRS representation", behavior)
	}

	var payload bytes.Buffer
	if err := WriteMrsFromStrategy(&payload, behavior, mrsStrategy); err != nil {
		return PreparedRuleProvider{}, err
	}
	sourceHash := sha256.Sum256(raw)
	payloadHash := sha256.Sum256(payload.Bytes())
	var envelope bytes.Buffer
	envelope.WriteString(sidecarMagic)
	envelope.WriteByte(byte(behavior))
	envelope.WriteByte(byte(format))
	envelope.Write(sourceHash[:])
	envelope.Write(payloadHash[:])
	envelope.Write(payload.Bytes())

	if err := publishPreparedSidecar(sidecar, envelope.Bytes()); err != nil {
		return PreparedRuleProvider{}, err
	}
	digest := extensionReadyDigest(behavior, format, strategy.Count(), raw, envelope.Bytes())
	return PreparedRuleProvider{
		Name: name, Path: sourcePath, Sidecar: sidecar,
		Behavior: behavior.String(), Format: format.String(),
		Count: strategy.Count(), Digest: digest,
	}, nil
}

func publishPreparedSidecar(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// Read back the exact artifact before returning its digest.
	published, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if sum, want := sha256.Sum256(published), sha256.Sum256(data); sum != want {
		return fmt.Errorf("published sidecar digest mismatch: got %s want %s", hex.EncodeToString(sum[:]), hex.EncodeToString(want[:]))
	}
	return nil
}
