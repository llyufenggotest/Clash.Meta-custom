package constant_test

import (
	"context"
	C "github.com/metacubex/mihomo/constant"
	"testing"
	"time"
)

func TestUDPAdmissionBudgetSharedAndCallerBound(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx, stop := C.WithUDPAdmissionBudget(parent)
	defer stop()
	d, _ := ctx.Deadline()
	pd, _ := parent.Deadline()
	if !d.Equal(pd) {
		t.Fatal("caller deadline extended")
	}
	child, done := C.WithUDPAdmissionBudget(ctx)
	defer done()
	if child != ctx {
		t.Fatal("nested admission reset total budget")
	}
	defaultCtx, finish := C.WithUDPAdmissionBudget(context.Background())
	defer finish()
	deadline, ok := defaultCtx.Deadline()
	if !ok || time.Until(deadline) > C.UDPAdmissionTimeout {
		t.Fatal("unbounded admission")
	}
	cancel()
	if ctx.Err() != context.Canceled || child.Err() != context.Canceled {
		t.Fatal("cancellation lost")
	}
}
