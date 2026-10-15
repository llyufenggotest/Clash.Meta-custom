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
type OwnedParser[V any] func(*Owner, []byte) (V, error)
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
	parser       OwnedParser[V]
	interval     time.Duration
	onUpdate     func(*Owner, V)
	watcher      *fswatch.Watcher
	loadSlot     chan struct{} // one operation; canceled callers never queue behind an external closure
	// The owner mutex protects short final commits and admission only.
	owner       *Owner
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
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	if !f.owner.closed {
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
	if err := f.owner.admit(); err != nil {
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
	if err := f.owner.admit(); err != nil {
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
		if err := f.owner.admit(); err != nil {
			return lo.Empty[V](), err
		}
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

// InitialFetch is network content acquired ahead of Initial. It has not been
// parsed or published as provider state. HTTP vehicles may update ETag/cache
// metadata during Read, using the Fetcher's publication owner.
type InitialFetch struct {
	data *initialFetchData
}

// A token is owner-bound and single-use even when copied. Consuming it drops
// the retained raw buffer before the preflight window can admit another read.
type initialFetchData struct {
	mu       sync.Mutex
	owner    *Owner
	buf      []byte
	hash     utils.HashType
	consumed bool
}

// FetchInitial performs only the remote acquisition that Initial would do when
// neither a local file nor a bundle file can satisfy it. It never parses,
// writes, publishes, or starts a pull loop, so callers may run it concurrently
// across different Fetchers and keep InitialFromFetch (the parse) sequential.
func (f *Fetcher[V]) FetchInitial() (InitialFetch, error) {
	if err := f.owner.admit(); err != nil {
		return InitialFetch{}, err
	}
	if f.vehicle.Type() != P.HTTP || f.bundleFile != nil {
		return InitialFetch{}, nil
	}
	if _, err := os.Stat(f.vehicle.Path()); err == nil {
		return InitialFetch{}, nil
	}
	if err := f.acquire(); err != nil {
		return InitialFetch{}, err
	}
	defer func() { <-f.loadSlot }()
	currentHash, _ := f.metadataSnapshot()
	buf, hash, err := f.vehicle.Read(P.WithPublicationOwner(f.ctx, f.owner), currentHash)
	if err != nil {
		f.backoff.AddAttempt()
		return InitialFetch{}, err
	}
	return InitialFetch{data: &initialFetchData{owner: f.owner, buf: buf, hash: hash}}, nil
}

// InitialFromFetch completes Initial. Without prefetched content it is exactly
// Initial; with it, it is Initial's remote branch minus the network read.
func (f *Fetcher[V]) InitialFromFetch(fetch InitialFetch) (V, error) {
	if fetch.data == nil {
		return f.Initial()
	}
	d := fetch.data
	d.mu.Lock()
	if d.owner != f.owner || d.consumed {
		d.mu.Unlock()
		return lo.Empty[V](), fmt.Errorf("invalid or consumed initial fetch token")
	}
	d.consumed = true
	buf, hash := d.buf, d.hash
	d.buf = nil
	d.mu.Unlock()
	if err := f.acquire(); err != nil {
		return lo.Empty[V](), err
	}
	defer func() { <-f.loadSlot }()
	contents, _, updateErr := f.loadBufAdmitted(buf, hash, true)
	if err := f.startPullLoop(false); err != nil {
		return lo.Empty[V](), err
	}
	if updateErr != nil {
		return lo.Empty[V](), updateErr
	}
	return contents, nil
}

func (f *Fetcher[V]) acquire() error {
	select {
	case <-f.ctx.Done():
		return context.Canceled
	case f.loadSlot <- struct{}{}:
	}
	if err := f.owner.admit(); err != nil {
		<-f.loadSlot
		return err
	}
	return nil
}

func (f *Fetcher[V]) Update() (V, bool, error) {
	if err := f.acquire(); err != nil {
		return lo.Empty[V](), false, err
	}
	defer func() { <-f.loadSlot }()
	currentHash, _ := f.metadataSnapshot()
	buf, hash, err := f.vehicle.Read(P.WithPublicationOwner(f.ctx, f.owner), currentHash)
	if err != nil {
		f.backoff.AddAttempt() // add a failed attempt to backoff
		return lo.Empty[V](), false, err
	}
	return f.loadBufAdmitted(buf, hash, f.vehicle.Type() != P.File)
}

func (f *Fetcher[V]) CommitState(state func()) error { return f.owner.Commit(state) }

func (f *Fetcher[V]) SideUpdate(buf []byte) (V, bool, error) {
	if err := f.owner.admit(); err != nil {
		return lo.Empty[V](), false, err
	}
	return f.loadBuf(buf, utils.MakeHash(buf), true)
}

func (f *Fetcher[V]) loadBuf(buf []byte, hash utils.HashType, updateFile bool) (V, bool, error) {
	if err := f.acquire(); err != nil {
		return lo.Empty[V](), false, err
	}
	defer func() { <-f.loadSlot }()
	return f.loadBufAdmitted(buf, hash, updateFile)
}

func (f *Fetcher[V]) loadBufAdmitted(buf []byte, hash utils.HashType, updateFile bool) (V, bool, error) {
	// Vehicle methods are external code: resolve outside the owner lock.
	path := f.vehicle.Path()
	now := time.Now()
	f.owner.mu.Lock()
	if f.owner.closed {
		f.owner.mu.Unlock()
		return lo.Empty[V](), false, context.Canceled
	}
	currentHash, _ := f.metadataSnapshot()
	if currentHash.Equal(hash) {
		defer f.owner.mu.Unlock()
		if updateFile {
			_ = os.Chtimes(path, now, now)
		}
		f.setUpdatedAt(now)
		f.backoff.Reset() // no error, reset backoff
		return lo.Empty[V](), true, nil
	}
	f.owner.mu.Unlock()

	if buf == nil { // f.hash has been changed between f.vehicle.Read but should not happen (cause by concurrent)
		return lo.Empty[V](), true, nil
	}

	if err := f.owner.admit(); err != nil {
		return lo.Empty[V](), false, err
	}
	contents, err := f.parser(f.owner, buf)
	if err != nil {
		f.backoff.AddAttempt() // add a failed attempt to backoff
		return lo.Empty[V](), false, err
	}
	if err = f.owner.admit(); err != nil {
		return lo.Empty[V](), false, err
	}
	var prepared *P.PreparedWrite
	if updateFile {
		if err = f.owner.admit(); err != nil {
			return lo.Empty[V](), false, err
		}
		if staged, ok := f.vehicle.(P.PreparedVehicle); ok {
			prepared, err = staged.PrepareWrite(f.ctx, buf)
			if err != nil {
				return lo.Empty[V](), false, err
			}
			defer prepared.Abort()
		} else {
			// Legacy Write is external, uncancellable code: admit before calling,
			// never hold the owner while it runs. Close prevents new admissions,
			// but cannot stop an admitted Write or roll back its disk effects.
			if err = f.owner.admit(); err != nil {
				return lo.Empty[V](), false, err
			}
			if err = f.vehicle.Write(buf); err != nil {
				return lo.Empty[V](), false, err
			}
		}
	}
	f.owner.mu.Lock()
	if f.owner.closed {
		f.owner.mu.Unlock()
		return lo.Empty[V](), false, context.Canceled
	}
	if prepared != nil {
		if err = prepared.Publish(); err != nil {
			f.owner.mu.Unlock()
			return lo.Empty[V](), false, err
		}
	}
	f.backoff.Reset()
	f.metadataMu.Lock()
	f.updatedAt = now
	f.hash = hash
	f.metadataMu.Unlock()
	// Reserve this invocation before Close can revoke the epoch. Close does
	// not join it. Owned callbacks recheck the owner at their final commit.
	callback := f.onUpdate
	f.owner.mu.Unlock()
	if callback != nil {
		callback(f.owner, contents)
	}
	return contents, false, nil
}

func (f *Fetcher[V]) Close() error {
	// Revoke the terminal owner; serialize only with short final commits.
	// Never join an external read/parser/onUpdate or write preparation.
	f.owner.mu.Lock()
	f.ctxCancel()
	f.owner.closed = true
	watcher := f.watcher
	f.watcher = nil
	f.owner.mu.Unlock()
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
	vehicleType, path := f.vehicle.Type(), f.vehicle.Path()
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	if f.owner.closed {
		return context.Canceled
	}
	if f.pullStarted {
		return nil
	}
	// pull contents automatically
	if vehicleType == P.File {
		f.watcher, err = fswatch.NewWatcher(fswatch.Options{
			Path:     []string{path},
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

// NewFetcher preserves legacy closures. An admitted closure may finish after
// Close; arbitrary side effects inside it are outside Fetcher's control. Use
// NewOwnedFetcher to cancel preparation and guard provider/cache commits.
func NewFetcher[V any](name string, interval time.Duration, vehicle P.Vehicle, bundleFile BundleFile, parser Parser[V], onUpdate func(V)) *Fetcher[V] {
	var callback func(*Owner, V)
	if onUpdate != nil {
		callback = func(_ *Owner, v V) { onUpdate(v) }
	}
	return NewOwnedFetcher(name, interval, vehicle, bundleFile, func(_ *Owner, b []byte) (V, error) { return parser(b) }, callback)
}

func NewOwnedFetcher[V any](name string, interval time.Duration, vehicle P.Vehicle, bundleFile BundleFile, parser OwnedParser[V], onUpdate func(*Owner, V)) *Fetcher[V] {
	ctx, cancel := context.WithCancel(context.Background())
	minBackoff := 10 * time.Second
	if interval < minBackoff {
		minBackoff = interval
	}
	return &Fetcher[V]{
		ctx:        ctx,
		owner:      &Owner{ctx: ctx},
		loadSlot:   make(chan struct{}, 1),
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
