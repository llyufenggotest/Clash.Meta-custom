package resource

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/slowdown"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/fswatch"
	"github.com/samber/lo"
)

type Parser[V any] func([]byte) (V, error)
type BundleFile func() (fs.File, error)

type Fetcher[V any] struct {
	ctx          context.Context
	ctxCancel    context.CancelFunc
	resourceType string
	name         string
	vehicle      P.Vehicle
	bundleFile   BundleFile
	metadataMu   sync.RWMutex // independent: provider JSON may hold readyMu
	updatedAt    time.Time
	hash         utils.HashType
	parser       Parser[V]
	interval     time.Duration
	onUpdate     func(V)
	watcher      *fswatch.Watcher
	loadBufMutex sync.Mutex
	// Serialize publication and background-resource admission with terminal Close.
	// Do not hold this lock across parser or vehicle.Read: neither is cancellable.
	lifecycleMu sync.Mutex
	closed      bool
	pullStarted bool
	backoff     slowdown.Backoff
}

func (f *Fetcher[V]) Name() string {
	return f.name
}

func (f *Fetcher[V]) Vehicle() P.Vehicle {
	return f.vehicle
}

func (f *Fetcher[V]) VehicleType() P.VehicleType {
	return f.vehicle.Type()
}

func (f *Fetcher[V]) UpdatedAt() time.Time {
	f.metadataMu.RLock()
	defer f.metadataMu.RUnlock()
	return f.updatedAt
}

func (f *Fetcher[V]) metadataSnapshot() (utils.HashType, time.Time) {
	f.metadataMu.RLock()
	defer f.metadataMu.RUnlock()
	return f.hash, f.updatedAt
}

func (f *Fetcher[V]) setInitialUpdatedAt(value time.Time) {
	f.lifecycleMu.Lock()
	defer f.lifecycleMu.Unlock()
	if !f.closed {
		f.setUpdatedAt(value)
	}
}

func (f *Fetcher[V]) setUpdatedAt(value time.Time) {
	f.metadataMu.Lock()
	f.updatedAt = value
	f.metadataMu.Unlock()
}

// InitialLocal admits only prepared disk content. It deliberately does not fall
// back to network/bundle after a parse failure, preserving the actionable cause.
func (f *Fetcher[V]) InitialLocal() (V, error) {
	if err := f.ctx.Err(); err != nil {
		return lo.Empty[V](), err
	}
	buf, err := os.ReadFile(f.vehicle.Path())
	if err != nil {
		return lo.Empty[V](), fmt.Errorf("prepared rules unavailable; prepare in app: %w", err)
	}
	contents, _, err := f.loadBuf(buf, utils.MakeHash(buf), false)
	if err != nil {
		return lo.Empty[V](), err
	}
	if err = f.startPullLoop(false); err != nil {
		return lo.Empty[V](), err
	}
	return contents, nil
}

func (f *Fetcher[V]) Initial() (V, error) {
	if err := f.ctx.Err(); err != nil {
		return lo.Empty[V](), err
	}
	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		// local file exists, use it first
		buf, err := os.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		contents, _, err := f.loadBuf(buf, utils.MakeHash(buf), false)
		f.setInitialUpdatedAt(modTime) // reset updatedAt to file's modTime

		if err == nil {
			err = f.startPullLoop(time.Since(modTime) > f.interval)
			if err != nil {
				return lo.Empty[V](), err
			}
			return contents, nil
		}
	}

	// parse local file error, fallback to bundle file
	if f.bundleFile != nil {
		// bundle file exists, use it first
		if file, fErr := f.bundleFile(); fErr == nil {
			defer file.Close()
			buf, err := io.ReadAll(file)
			var modTime time.Time
			if stat, sErr := file.Stat(); sErr == nil {
				modTime = stat.ModTime()
			}
			contents, _, err := f.loadBuf(buf, utils.MakeHash(buf), true)
			f.setInitialUpdatedAt(modTime) // reset updatedAt to file's modTime

			if err == nil {
				log.Infoln("[Provider] %s extract successful from bundle file", f.Name())
				err = f.startPullLoop(time.Since(modTime) > f.interval)
				if err != nil {
					return lo.Empty[V](), err
				}
				return contents, nil
			}
			log.Warnln("[Provider] %s read bundle file error: %s", f.Name(), err.Error())
		} else {
			log.Warnln("[Provider] %s read bundle file error: %s", f.Name(), fErr.Error())
		}
	}

	// parse local file error, fallback to remote
	contents, _, updateErr := f.Update()

	// start the pull loop even if f.Update() failed
	err := f.startPullLoop(false)
	if err != nil {
		return lo.Empty[V](), err
	}

	if updateErr != nil {
		return lo.Empty[V](), updateErr
	}

	return contents, nil
}

func (f *Fetcher[V]) Update() (V, bool, error) {
	currentHash, _ := f.metadataSnapshot()
	buf, hash, err := f.vehicle.Read(f.ctx, currentHash)
	if err != nil {
		f.backoff.AddAttempt() // add a failed attempt to backoff
		return lo.Empty[V](), false, err
	}
	return f.loadBuf(buf, hash, f.vehicle.Type() != P.File)
}

func (f *Fetcher[V]) SideUpdate(buf []byte) (V, bool, error) {
	return f.loadBuf(buf, utils.MakeHash(buf), true)
}

func (f *Fetcher[V]) loadBuf(buf []byte, hash utils.HashType, updateFile bool) (V, bool, error) {
	f.loadBufMutex.Lock()
	defer f.loadBufMutex.Unlock()

	now := time.Now()
	f.lifecycleMu.Lock()
	if f.closed {
		f.lifecycleMu.Unlock()
		return lo.Empty[V](), false, context.Canceled
	}
	currentHash, _ := f.metadataSnapshot()
	if currentHash.Equal(hash) {
		defer f.lifecycleMu.Unlock()
		if updateFile {
			_ = os.Chtimes(f.vehicle.Path(), now, now)
		}
		f.setUpdatedAt(now)
		f.backoff.Reset() // no error, reset backoff
		return lo.Empty[V](), true, nil
	}
	f.lifecycleMu.Unlock()

	if buf == nil { // f.hash has been changed between f.vehicle.Read but should not happen (cause by concurrent)
		return lo.Empty[V](), true, nil
	}

	contents, err := f.parser(buf)
	if err != nil {
		f.backoff.AddAttempt() // add a failed attempt to backoff
		return lo.Empty[V](), false, err
	}
	f.lifecycleMu.Lock()
	defer f.lifecycleMu.Unlock()
	if f.closed {
		return lo.Empty[V](), false, context.Canceled
	}
	f.backoff.Reset() // no error, reset backoff

	if updateFile {
		if err = f.vehicle.Write(buf); err != nil {
			return lo.Empty[V](), false, err
		}
	}
	f.metadataMu.Lock()
	f.updatedAt = now
	f.hash = hash
	f.metadataMu.Unlock()

	if f.onUpdate != nil {
		f.onUpdate(contents)
	}

	return contents, false, nil
}

func (f *Fetcher[V]) Close() error {
	// Cancel immediately; serialize only with commits, not a pending read/parser.
	f.ctxCancel()
	f.lifecycleMu.Lock()
	f.closed = true
	watcher := f.watcher
	f.watcher = nil
	f.lifecycleMu.Unlock()
	if watcher != nil {
		_ = watcher.Close()
	}
	return nil
}

func (f *Fetcher[V]) pullLoop(forceUpdate bool) {
	_, updatedAt := f.metadataSnapshot()
	initialInterval := f.interval - time.Since(updatedAt)
	if initialInterval > f.interval {
		initialInterval = f.interval
	}

	if forceUpdate {
		log.Warnln("[Provider] %s not updated for a long time, force refresh", f.Name())
		f.updateWithLog()
	}
	if attempt := f.backoff.Attempt(); attempt > 0 { // f.Update() was failed, decrease the interval from backoff to achieve fast retry
		if duration := f.backoff.ForAttempt(attempt); duration < initialInterval {
			initialInterval = duration
		}
	}

	timer := time.NewTimer(initialInterval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			f.updateWithLog()
			interval := f.interval
			if attempt := f.backoff.Attempt(); attempt > 0 { // f.Update() was failed, decrease the interval from backoff to achieve fast retry
				if duration := f.backoff.ForAttempt(attempt); duration < interval {
					interval = duration
				}
			}
			timer.Reset(interval)
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *Fetcher[V]) startPullLoop(forceUpdate bool) (err error) {
	f.lifecycleMu.Lock()
	defer f.lifecycleMu.Unlock()
	if f.closed {
		return context.Canceled
	}
	if f.pullStarted {
		return nil
	}
	// pull contents automatically
	if f.vehicle.Type() == P.File {
		f.watcher, err = fswatch.NewWatcher(fswatch.Options{
			Path:     []string{f.vehicle.Path()},
			Callback: f.updateCallback,
		})
		if err != nil {
			return err
		}
		err = f.watcher.Start()
		if err != nil {
			_ = f.watcher.Close()
			f.watcher = nil
			return err
		}
	} else if f.interval > 0 {
		go f.pullLoop(forceUpdate)
	}
	f.pullStarted = true
	return
}

func (f *Fetcher[V]) updateCallback(path string) {
	f.updateWithLog()
}

func (f *Fetcher[V]) updateWithLog() {
	_, same, err := f.Update()
	if err != nil {
		log.Warnln("[Provider] %s pull error: %s", f.Name(), err.Error())
		return
	}

	if same {
		log.Debugln("[Provider] %s's content doesn't change", f.Name())
		return
	}

	log.Infoln("[Provider] %s's content update", f.Name())
	return
}

func NewFetcher[V any](name string, interval time.Duration, vehicle P.Vehicle, bundleFile BundleFile, parser Parser[V], onUpdate func(V)) *Fetcher[V] {
	ctx, cancel := context.WithCancel(context.Background())
	minBackoff := 10 * time.Second
	if interval < minBackoff {
		minBackoff = interval
	}
	return &Fetcher[V]{
		ctx:        ctx,
		ctxCancel:  cancel,
		name:       name,
		bundleFile: bundleFile,
		vehicle:    vehicle,
		parser:     parser,
		onUpdate:   onUpdate,
		interval:   interval,
		backoff: slowdown.Backoff{
			Factor: 2,
			Jitter: false,
			Min:    minBackoff,
			Max:    interval,
		},
	}
}
