package tunnel

import (
	"context"
	C "github.com/metacubex/mihomo/constant"
)

// Keep Proxy health/history identity while pinning the admitted packet adapter.
// No URLTest is run by admission and cancellation never marks a node unhealthy.
type udpAdmittedProxy struct {
	C.Proxy
	admitted C.ProxyAdapter
}

func (p *udpAdmittedProxy) SupportUDP() bool { return p.admitted.SupportUDP() }
func (p *udpAdmittedProxy) AdmitUDP(ctx context.Context, _ *C.Metadata) (C.ProxyAdapter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *udpAdmittedProxy) ListenPacketContext(ctx context.Context, m *C.Metadata) (C.PacketConn, error) {
	return p.admitted.ListenPacketContext(ctx, m)
}
func admitUDPProxy(ctx context.Context, p C.Proxy, m *C.Metadata) (C.Proxy, error) {
	a, err := C.AdmitUDP(ctx, p, m)
	if err != nil {
		return nil, err
	}
	if a == p {
		return p, nil
	}
	return &udpAdmittedProxy{Proxy: p, admitted: a}, nil
}
