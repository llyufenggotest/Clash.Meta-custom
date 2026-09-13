package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
)

// PreparedProxyProvider is the immutable result of validating one proxy
// provider and publishing its exact source bytes to caller-owned staging.
type PreparedProxyProvider struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Count   int    `json:"count"`
	Digest  string `json:"digest"`
	Vehicle string `json:"vehicle"`
}

// PrepareProxyProvider fetches or reads a provider once, fully parses every
// proxy, then atomically publishes the validated bytes to staging. It never
// creates a Fetcher/provider, starts health checks, watchers, or pull loops, and
// passes no active tunnel into proxy parsing.
func PrepareProxyProvider(ctx context.Context, name string, mapping map[string]any, targetPath string, trustedRoot string, timeout time.Duration) (PreparedProxyProvider, error) {
	if name == "" {
		return PreparedProxyProvider{}, fmt.Errorf("provider name is empty")
	}
	if targetPath == "" || trustedRoot == "" || !filepath.IsAbs(targetPath) || !filepath.IsAbs(trustedRoot) {
		return PreparedProxyProvider{}, fmt.Errorf("provider target and trusted root paths must be absolute")
	}
	targetPath = filepath.Clean(targetPath)
	trustedRoot = filepath.Clean(trustedRoot)
	if rel, relErr := filepath.Rel(trustedRoot, targetPath); relErr != nil || !filepath.IsLocal(rel) {
		return PreparedProxyProvider{}, fmt.Errorf("provider target path is outside trusted root")
	}
	if info, statErr := os.Lstat(targetPath); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return PreparedProxyProvider{}, fmt.Errorf("provider target path must not be a symlink")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return PreparedProxyProvider{}, statErr
	}
	if timeout <= 0 {
		return PreparedProxyProvider{}, fmt.Errorf("provider timeout must be positive")
	}
	if err := ctx.Err(); err != nil {
		return PreparedProxyProvider{}, err
	}

	schema := &proxyProviderSchema{HealthCheck: healthCheckSchema{Lazy: true}}
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	if err := decoder.Decode(mapping, schema); err != nil {
		return PreparedProxyProvider{}, err
	}
	parser, err := NewProxiesParser(name, nil, schema.Filter, schema.ExcludeFilter, schema.ExcludeType, schema.DialerProxy, schema.Override, schema.AgeSecretKey)
	if err != nil {
		return PreparedProxyProvider{}, err
	}
	if schema.Proxy != "" && schema.Proxy != "DIRECT" {
		return PreparedProxyProvider{}, fmt.Errorf("provider proxy %q is not supported by isolated prewarm", schema.Proxy)
	}

	var (
		buf     []byte
		vehicle string
	)
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch schema.Type {
	case "file":
		vehicle = "file"
		if schema.Path == "" {
			return PreparedProxyProvider{}, fmt.Errorf("file provider path is empty")
		}
		path := C.Path.Resolve(schema.Path)
		if !C.Path.IsSafePath(path) {
			return PreparedProxyProvider{}, C.Path.ErrNotSafePath(path)
		}
		buf, err = readBoundedFile(readCtx, path, 32<<20)
	case "http":
		vehicle = "http"
		if schema.URL == "" {
			return PreparedProxyProvider{}, fmt.Errorf("http provider url is empty")
		}
		buf, _, err = resource.NewIsolatedHTTPVehicle(schema.URL, targetPath, schema.Header, timeout, schema.SizeLimit, dialer.NewDialer()).Read(readCtx, utils.HashType{})
	case "inline":
		vehicle = "inline"
		ps := ProxySchema{Proxies: schema.Payload}
		buf, err = yaml.Marshal(ps)
	default:
		return PreparedProxyProvider{}, fmt.Errorf("%w: %s", errVehicleType, schema.Type)
	}
	if err != nil {
		return PreparedProxyProvider{}, err
	}
	if err := readCtx.Err(); err != nil {
		return PreparedProxyProvider{}, err
	}
	proxies, err := parser(buf)
	if err != nil {
		return PreparedProxyProvider{}, err
	}
	for _, proxy := range proxies {
		defer proxy.Close()
	}
	if err := publishPreparedProxy(targetPath, trustedRoot, buf); err != nil {
		return PreparedProxyProvider{}, err
	}
	sum := sha256.Sum256(buf)
	return PreparedProxyProvider{Name: name, Path: targetPath, Count: len(proxies), Digest: hex.EncodeToString(sum[:]), Vehicle: vehicle}, nil
}

func readBoundedFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("file provider exceeds %d byte limit", limit)
	}
	buf := make([]byte, 0, info.Size())
	chunk := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := file.Read(chunk)
		if n > 0 {
			if int64(len(buf)+n) > limit {
				return nil, fmt.Errorf("file provider exceeds %d byte limit", limit)
			}
			buf = append(buf, chunk[:n]...)
		}
		if readErr == io.EOF {
			return buf, nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func rejectLinkedPathComponents(path string, root string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(rel) {
		return fmt.Errorf("path is outside trusted root")
	}
	current := root
	for _, component := range append([]string{"."}, splitPath(rel)...) {
		if component != "." {
			current = filepath.Join(current, component)
		}
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("linked path component: %s", current)
		}
	}
	return nil
}

func splitPath(rel string) []string {
	var components []string
	for rel != "." && rel != "" {
		dir, base := filepath.Split(rel)
		if base != "" {
			components = append([]string{base}, components...)
		}
		rel = filepath.Clean(dir)
	}
	return components
}

func publishPreparedProxy(path string, trustedRoot string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := rejectLinkedPathComponents(dir, trustedRoot); err != nil {
		return fmt.Errorf("unsafe provider staging path: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := rejectLinkedPathComponents(dir, trustedRoot); err != nil {
		return fmt.Errorf("unsafe provider staging path before rename: %w", err)
	}
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("provider target path became a symlink")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return statErr
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	published, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if sha256.Sum256(published) != sha256.Sum256(data) {
		return fmt.Errorf("published proxy provider digest mismatch")
	}
	return nil
}
