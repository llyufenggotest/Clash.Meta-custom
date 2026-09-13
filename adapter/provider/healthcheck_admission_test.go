package provider

import (
	"context"
	"testing"
)

func TestSuspendHealthCheckCancelsActiveAdmission(t *testing.T) {
	SuspendHealthCheck(false)
	t.Cleanup(func() { SuspendHealthCheck(false) })

	ctx, release, admitted := acquireHealthCheckAdmission(context.Background())
	if !admitted {
		t.Fatal("health check was not admitted before suspension")
	}
	defer release()

	SuspendHealthCheck(true)
	select {
	case <-ctx.Done():
	default:
		t.Fatal("active health check context was not cancelled")
	}
	if _, releaseBlocked, admittedBlocked := acquireHealthCheckAdmission(context.Background()); admittedBlocked {
		releaseBlocked()
		t.Fatal("health check admitted while suspended")
	}

	SuspendHealthCheck(false)
	_, releaseResumed, admittedResumed := acquireHealthCheckAdmission(context.Background())
	if !admittedResumed {
		t.Fatal("health check was not admitted after resume")
	}
	releaseResumed()
}
