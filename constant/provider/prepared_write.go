package provider

import (
	"context"
	"os"
	"path/filepath"
)

// PreparedWrite owns a unique, fully written same-directory staging file.
// Publish contains only the final OS rename; no arbitrary Vehicle code is run
// under a Fetcher's owner lock. Close never waits for PrepareFileWrite's I/O.
// Rename itself is synchronous: no hard OS/filesystem latency bound is claimed.
type PreparedWrite struct{ temporary, target string }

func (w *PreparedWrite) Publish() error { return os.Rename(w.temporary, w.target) }
func (w *PreparedWrite) Abort()         { _ = os.Remove(w.temporary) }

func PrepareFileWrite(ctx context.Context, path string, buf []byte) (*PreparedWrite, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	w := &PreparedWrite{temporary: tmp.Name(), target: path}
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			w.Abort()
		}
	}()
	// Preserve an existing cache's access mode; a new staging/cache stays
	// private (CreateTemp 0600). Do not chmod a new file to world-writable.
	if stat, statErr := os.Stat(path); statErr == nil {
		if err = tmp.Chmod(stat.Mode().Perm()); err != nil {
			return nil, err
		}
	}
	// Bounded chunks check cancellation; a single OS write/sync may not cancel.
	for len(buf) > 0 {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		n := len(buf)
		if n > 64*1024 {
			n = 64 * 1024
		}
		if _, err = tmp.Write(buf[:n]); err != nil {
			return nil, err
		}
		buf = buf[n:]
	}
	if err = tmp.Sync(); err != nil {
		return nil, err
	}
	if err = tmp.Close(); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	keep = true
	return w, nil
}
