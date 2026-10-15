package constant

import (
	"context"
	"errors"
	"time"
)

// UDPAdmission is an optional, effectful request operation, not a capability
// query. Return the adapter pinned for this request; unknown is never support.
// Implementations must use ctx for all work and return selected-node rejection
// as an error other than bare ErrNotSupport (which preserves legacy rule skip).
type UDPAdmission interface {
	AdmitUDP(ctx context.Context, metadata *Metadata) (ProxyAdapter, error)
}

const UDPAdmissionTimeout = 5 * time.Second
const UDPAdmissionMaxDepth = 16

var ErrUDPAdmissionLoop = errors.New("UDP admission nesting limit exceeded")

type udpAdmissionBudgetKey struct{}
type udpAdmissionDepthKey struct{}

// WithUDPAdmissionBudget shares one total budget across wrappers, rule scanning
// and repeated admission. It never extends an earlier caller deadline.
func WithUDPAdmissionBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Value(udpAdmissionBudgetKey{}).(bool); ok {
		return ctx, func() {}
	}
	ctx, cancel := context.WithTimeout(ctx, UDPAdmissionTimeout)
	return context.WithValue(ctx, udpAdmissionBudgetKey{}, true), cancel
}

func AdmitUDP(ctx context.Context, adapter ProxyAdapter, metadata *Metadata) (ProxyAdapter, error) {
	ctx, cancel := WithUDPAdmissionBudget(ctx)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	depth, _ := ctx.Value(udpAdmissionDepthKey{}).(int)
	if depth >= UDPAdmissionMaxDepth {
		return nil, ErrUDPAdmissionLoop
	}
	ctx = context.WithValue(ctx, udpAdmissionDepthKey{}, depth+1)
	if a, ok := adapter.(UDPAdmission); ok {
		admitted, err := a.AdmitUDP(ctx, metadata)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		if admitted == nil {
			return nil, ErrNotSupport
		}
		return admitted, nil
	}
	if adapter != nil && adapter.SupportUDP() {
		return adapter, nil
	}
	return nil, ErrNotSupport
}
