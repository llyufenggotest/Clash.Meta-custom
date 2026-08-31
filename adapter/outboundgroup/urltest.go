package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

type URLTestOption struct {
	Tolerance uint16 `group:"tolerance,omitempty"`
}

type URLTest struct {
	*GroupBase
	selected       string
	testUrl        string
	expectedStatus string
	tolerance      uint16
	disableUDP     bool
	fastNode       C.Proxy
	fastSingle     *singledo.Single[C.Proxy]

	// cachedFastNode is the node this group resolved to on a previous run,
	// loaded once from the on-disk cache. Before any health check has produced
	// delay data, a url-test group otherwise falls back to proxies[0], which on
	// a real subscription is frequently a dead node — the user then waits out
	// several dial timeouts before traffic flows. Seeding from the last
	// known-good node makes a cold start route immediately, while the periodic
	// health check still switches to a faster node when one is found.
	cachedFastNode     string
	cachedFastNodeOnce sync.Once
	persistedFastNode  string
}

// fastNodePersister lets the group write its resolved node back to the profile
// cache without importing that package directly (which would create an import
// cycle). executor wires it up at startup.
var fastNodePersister func(group, node string)

// SetFastNodePersister registers the sink used to remember a url-test group's
// resolved node across restarts. Nil-safe: if never set, the cache is simply
// not written and behaviour is unchanged.
func SetFastNodePersister(fn func(group, node string)) {
	fastNodePersister = fn
}

// fastNodeLoader supplies the previously cached node for a group at startup.
var fastNodeLoader func(group string) string

// SetFastNodeLoader registers the source of the last known-good node per group.
func SetFastNodeLoader(fn func(group string) string) {
	fastNodeLoader = fn
}

func (u *URLTest) Now() string {
	return u.fast(false).Name()
}

func (u *URLTest) Set(name string) error {
	var p C.Proxy
	for _, proxy := range u.GetProxies(false) {
		if proxy.Name() == name {
			p = proxy
			break
		}
	}
	if p == nil {
		return errors.New("proxy not exist")
	}
	u.ForceSet(name)
	return nil
}

func (u *URLTest) ForceSet(name string) {
	u.selected = name
	u.fastSingle.Reset()
}

// DialContext implements C.ProxyAdapter
func (u *URLTest) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxy := u.fast(true)
	c, err = proxy.DialContext(ctx, metadata)
	if err == nil {
		c.AppendToChains(u)
	} else {
		u.onDialFailed(proxy.Type(), err, u.healthCheck)
	}

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err == nil {
				u.onDialSuccess()
			} else {
				u.onDialFailed(proxy.Type(), err, u.healthCheck)
			}
		})
	}

	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (u *URLTest) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	proxy := u.fast(true)
	pc, err := proxy.ListenPacketContext(ctx, metadata)
	if err == nil {
		pc.AppendToChains(u)
	} else {
		u.onDialFailed(proxy.Type(), err, u.healthCheck)
	}

	return pc, err
}

// Unwrap implements C.ProxyAdapter
func (u *URLTest) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return u.fast(touch)
}

func (u *URLTest) healthCheck() {
	u.fastSingle.Reset()
	u.GroupBase.healthCheck()
	u.fastSingle.Reset()
}

func (u *URLTest) fast(touch bool) C.Proxy {
	elm, _, shared := u.fastSingle.Do(func() (C.Proxy, error) {
		proxies := u.GetProxies(touch)
		if u.selected != "" {
			for _, proxy := range proxies {
				if !proxy.AliveForTestUrl(u.testUrl) {
					continue
				}
				if proxy.Name() == u.selected {
					u.fastNode = proxy
					return proxy, nil
				}
			}
		}

		fast := proxies[0]
		minDelay := fast.LastDelayForTestUrl(u.testUrl)
		fastNotExist := true

		for _, proxy := range proxies[1:] {
			if u.fastNode != nil && proxy.Name() == u.fastNode.Name() {
				fastNotExist = false
			}

			if !proxy.AliveForTestUrl(u.testUrl) {
				continue
			}

			delay := proxy.LastDelayForTestUrl(u.testUrl)
			if delay < minDelay {
				fast = proxy
				minDelay = delay
			}

		}
		// tolerance
		if u.fastNode == nil || fastNotExist || !u.fastNode.AliveForTestUrl(u.testUrl) || u.fastNode.LastDelayForTestUrl(u.testUrl) > fast.LastDelayForTestUrl(u.testUrl)+u.tolerance {
			u.fastNode = fast
		}

		// Cold start: no proxy has delay data yet, so the block above just
		// picked proxies[0] with a zero delay — frequently a dead node. If a
		// previous run left us a known-good node that still exists in this
		// group, prefer it so the very first packet routes through something
		// that actually worked, instead of stalling on dial timeouts until the
		// health check finishes.
		if u.noDelayData() {
			if cached := u.loadCachedFastNode(); cached != "" {
				for _, proxy := range proxies {
					if proxy.Name() == cached {
						u.fastNode = proxy
						log.Infoln("[URLTest] %s cold-started on cached fast node %s (no delay data yet)", u.Name(), cached)
						break
					}
				}
			}
		}

		u.persistFastNode(u.fastNode.Name())
		return u.fastNode, nil
	})
	if shared && touch { // a shared fastSingle.Do() may cause providers untouched, so we touch them again
		u.Touch()
	}

	return elm
}

// noDelayData reports whether the health check has yet to record a live delay
// for any node in the group. Proxy.LastDelayForTestUrl returns the sentinel
// 0xffff when a node has no recorded delay for this test URL, so "has data"
// means a value strictly below that sentinel. In the no-data window the normal
// smallest-delay comparison is meaningless and the cached node should win.
func (u *URLTest) noDelayData() bool {
	const noDelaySentinel uint16 = 0xffff
	for _, proxy := range u.GetProxies(false) {
		if proxy.LastDelayForTestUrl(u.testUrl) < noDelaySentinel {
			return false
		}
	}
	return true
}

// loadCachedFastNode reads the last known-good node exactly once per group.
func (u *URLTest) loadCachedFastNode() string {
	u.cachedFastNodeOnce.Do(func() {
		if fastNodeLoader != nil {
			u.cachedFastNode = fastNodeLoader(u.Name())
		}
	})
	return u.cachedFastNode
}

// persistFastNode writes the resolved node back to the cache when it changes,
// so the next cold start can use it. Cheap dedupe avoids a bbolt write on every
// dial.
func (u *URLTest) persistFastNode(node string) {
	if node == "" || node == u.persistedFastNode {
		return
	}
	u.persistedFastNode = node
	if fastNodePersister != nil {
		fastNodePersister(u.Name(), node)
	}
}

// SupportUDP implements C.ProxyAdapter
func (u *URLTest) SupportUDP() bool {
	if u.disableUDP {
		return false
	}
	return u.fast(false).SupportUDP()
}

// IsL3Protocol implements C.ProxyAdapter
func (u *URLTest) IsL3Protocol(metadata *C.Metadata) bool {
	return u.fast(false).IsL3Protocol(metadata)
}

// MarshalJSON implements C.ProxyAdapter
func (u *URLTest) MarshalJSON() ([]byte, error) {
	all := []string{}
	for _, proxy := range u.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":           u.Type().String(),
		"now":            u.Now(),
		"all":            all,
		"testUrl":        u.testUrl,
		"expectedStatus": u.expectedStatus,
		"fixed":          u.selected,
		"hidden":         u.Hidden(),
		"icon":           u.Icon(),
		"emptyFallback":  u.EmptyFallback().Name(),
	})
}

func (u *URLTest) Providers() []P.ProxyProvider {
	return u.providers
}

func (u *URLTest) Proxies() []C.Proxy {
	return u.GetProxies(false)
}

func (u *URLTest) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	return u.GroupBase.URLTest(ctx, u.testUrl, expectedStatus)
}

func NewURLTest(option GroupCommonOption, urlTestOption URLTestOption, emptyFallback C.Proxy, providers []P.ProxyProvider) (*URLTest, error) {
	if emptyFallback == nil {
		return nil, errors.New("empty fallback proxy not exist")
	}
	urlTest := &URLTest{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.URLTest,
			Hidden:         option.Hidden,
			Icon:           option.Icon,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			EmptyFallback:  emptyFallback,
			Providers:      providers,
		}),
		fastSingle:     singledo.NewSingle[C.Proxy](time.Second * 10),
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		tolerance:      urlTestOption.Tolerance,
	}

	return urlTest, nil
}
