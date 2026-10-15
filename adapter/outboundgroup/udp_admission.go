package outboundgroup

import (
	"context"
	C "github.com/metacubex/mihomo/constant"
)

// udpRequest pins selection once, including round-robin groups. Admission never
// touches providers/health checks; only actual packet entry appends group chains.
type udpRequest struct {
	C.ProxyAdapter
	child C.ProxyAdapter
}

func (r *udpRequest) AdmitUDP(ctx context.Context, _ *C.Metadata) (C.ProxyAdapter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *udpRequest) SupportUDP() bool { return r.child.SupportUDP() }
func (r *udpRequest) ListenPacketContext(ctx context.Context, m *C.Metadata) (C.PacketConn, error) {
	pc, err := r.child.ListenPacketContext(ctx, m)
	if err == nil {
		pc.AppendToChains(r.ProxyAdapter)
	}
	return pc, err
}
func (r *udpRequest) Unwrap(*C.Metadata, bool) C.Proxy { return nil }

func admitGroupUDP(ctx context.Context, group C.ProxyAdapter, child C.Proxy, disabled bool, m *C.Metadata) (C.ProxyAdapter, error) {
	if disabled {
		return nil, C.ErrNotSupport
	}
	a, err := C.AdmitUDP(ctx, child, m)
	if err != nil {
		return nil, err
	}
	return &udpRequest{ProxyAdapter: group, child: a}, nil
}
func (s *Selector) AdmitUDP(ctx context.Context, m *C.Metadata) (C.ProxyAdapter, error) {
	if s.disableUDP {
		return nil, C.ErrNotSupport
	}
	return admitGroupUDP(ctx, s, s.Unwrap(m, false), false, m)
}
func (s *Fallback) AdmitUDP(ctx context.Context, m *C.Metadata) (C.ProxyAdapter, error) {
	if s.disableUDP {
		return nil, C.ErrNotSupport
	}
	return admitGroupUDP(ctx, s, s.Unwrap(m, false), false, m)
}
func (s *URLTest) AdmitUDP(ctx context.Context, m *C.Metadata) (C.ProxyAdapter, error) {
	if s.disableUDP {
		return nil, C.ErrNotSupport
	}
	return admitGroupUDP(ctx, s, s.Unwrap(m, false), false, m)
}
func (s *LoadBalance) AdmitUDP(ctx context.Context, m *C.Metadata) (C.ProxyAdapter, error) {
	if s.disableUDP {
		return nil, C.ErrNotSupport
	}
	// Reserve the round-robin selection exactly once for this actual request.
	return admitGroupUDP(ctx, s, s.Unwrap(m, true), false, m)
}
