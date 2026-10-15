package inner

import (
	"errors"
	"net"
	"sync/atomic"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

// current is read by any goroutine that issues a core HTTP request while a
// config is applied or released, so it must be published atomically.
var current atomic.Pointer[C.Tunnel]

// New installs t for inner requests. New(nil) releases routing so inner HTTP
// callers fall back to a direct dial instead of a tunnel with no config.
func New(t C.Tunnel) {
	if t == nil {
		current.Store(nil)
		return
	}
	current.Store(&t)
}

func GetTunnel() C.Tunnel {
	if t := current.Load(); t != nil {
		return *t
	}
	return nil
}

func HandleTcp(tunnel C.Tunnel, address string, proxy string) (conn net.Conn, err error) {
	if tunnel == nil {
		return nil, errors.New("tunnel uninitialized")
	}
	// executor Parsed
	conn1, conn2 := N.Pipe()

	metadata := &C.Metadata{}
	metadata.NetWork = C.TCP
	metadata.Type = C.INNER
	metadata.DNSMode = C.DNSNormal
	metadata.Process = C.MihomoName
	if proxy != "" {
		metadata.SpecialProxy = proxy
	}
	if err = metadata.SetRemoteAddress(address); err != nil {
		return nil, err
	}

	go tunnel.HandleTCPConn(conn2, metadata)
	return conn1, nil
}
