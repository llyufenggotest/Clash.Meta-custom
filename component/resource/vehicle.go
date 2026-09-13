package resource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/metacubex/http"
)

const (
	DefaultHttpTimeout = time.Second * 20

	fileMode os.FileMode = 0o666
	dirMode  os.FileMode = 0o755
)

var (
	etag = false
)

func ETag() bool {
	return etag
}

func SetETag(b bool) {
	etag = b
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	return os.WriteFile(path, buf, fileMode)
}

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() P.VehicleType {
	return P.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (f *FileVehicle) Url() string {
	return "file://" + f.path
}

func (f *FileVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	buf, err = os.ReadFile(f.path)
	if err != nil {
		return
	}
	hash = utils.MakeHash(buf)
	return
}

func (f *FileVehicle) Proxy() string {
	return ""
}

func (f *FileVehicle) Write(buf []byte) error {
	return safeWrite(f.path, buf)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

type HTTPVehicle struct {
	url       string
	path      string
	proxy     string
	header    http.Header
	timeout   time.Duration
	sizeLimit int64
	inRead    func(response *http.Response)
	provider  P.ProxyProvider
	etag      *bool
	dialer    C.Dialer
}

func (h *HTTPVehicle) Url() string {
	return h.url
}

func (h *HTTPVehicle) Type() P.VehicleType {
	return P.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Proxy() string {
	return h.proxy
}

func (h *HTTPVehicle) Write(buf []byte) error {
	return safeWrite(h.path, buf)
}

func (h *HTTPVehicle) SetInRead(fn func(response *http.Response)) {
	h.inRead = fn
}

func (h *HTTPVehicle) Read(ctx context.Context, oldHash utils.HashType) (buf []byte, hash utils.HashType, err error) {
	ctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	header := h.header
	setIfNoneMatch := false
	useETag := etag
	if h.etag != nil {
		useETag = *h.etag
	}
	if useETag && oldHash.IsValid() {
		etagWithHash := cachefile.Cache().GetETagWithHash(h.url)
		if oldHash.Equal(etagWithHash.Hash) && etagWithHash.ETag != "" {
			if header == nil {
				header = http.Header{}
			} else {
				header = header.Clone()
			}
			header.Set("If-None-Match", etagWithHash.ETag)
			setIfNoneMatch = true
		}
	}
	requestOptions := []mihomoHttp.Option{mihomoHttp.WithSpecialProxy(h.proxy)}
	if h.dialer != nil {
		requestOptions = []mihomoHttp.Option{mihomoHttp.WithDialer(h.dialer)}
	}
	resp, err := mihomoHttp.HttpRequest(ctx, h.url, http.MethodGet, header, nil, requestOptions...)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if h.inRead != nil {
		h.inRead(resp)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if setIfNoneMatch && resp.StatusCode == http.StatusNotModified {
			return nil, oldHash, nil
		}
		err = errors.New(resp.Status)
		return
	}
	var reader io.Reader = resp.Body
	if h.sizeLimit > 0 {
		reader = io.LimitReader(reader, h.sizeLimit)
	} else if h.sizeLimit < 0 {
		limit := -h.sizeLimit
		reader = io.LimitReader(reader, limit+1)
	}
	buf, err = io.ReadAll(reader)
	if err != nil {
		return
	}
	if h.sizeLimit < 0 && int64(len(buf)) > -h.sizeLimit {
		err = fmt.Errorf("provider response exceeds size-limit")
		buf = nil
		return
	}
	hash = utils.MakeHash(buf)
	if useETag {
		cachefile.Cache().SetETagWithHash(h.url, cachefile.EtagWithHash{
			Hash: hash,
			ETag: resp.Header.Get("ETag"),
			Time: time.Now(),
		})
	}
	return
}

func NewHTTPVehicle(url string, path string, proxy string, header http.Header, timeout time.Duration, sizeLimit int64) *HTTPVehicle {
	return &HTTPVehicle{
		url:       url,
		path:      path,
		proxy:     proxy,
		header:    header,
		timeout:   timeout,
		sizeLimit: sizeLimit,
	}
}

const isolatedHTTPVehicleMaxSize int64 = 32 << 20

// NewIsolatedHTTPVehicle disables shared ETag cache reads and writes and
// forces an explicit dialer so candidate preparation never uses the live tunnel.
func NewIsolatedHTTPVehicle(url string, path string, header http.Header, timeout time.Duration, sizeLimit int64, isolatedDialer C.Dialer) *HTTPVehicle {
	if sizeLimit <= 0 || sizeLimit > isolatedHTTPVehicleMaxSize {
		sizeLimit = isolatedHTTPVehicleMaxSize
	}
	vehicle := NewHTTPVehicle(url, path, "", header, timeout, -sizeLimit)
	vehicle.dialer = isolatedDialer
	disabled := false
	vehicle.etag = &disabled
	return vehicle
}
