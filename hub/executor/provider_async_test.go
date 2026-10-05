package executor

import (
	"testing"
	"time"

	P "github.com/metacubex/mihomo/constant/provider"
)

type blockingProvider struct {
	started chan struct{}
	release chan struct{}
}

func (p *blockingProvider) Name() string               { return "blocking" }
func (p *blockingProvider) VehicleType() P.VehicleType { return P.HTTP }
func (p *blockingProvider) Type() P.ProviderType       { return P.Proxy }
func (p *blockingProvider) Update() error              { return nil }
func (p *blockingProvider) Initial() error {
	close(p.started)
	<-p.release
	return nil
}

func TestLoadProviderDoesNotBlockConfigApply(t *testing.T) {
	provider := &blockingProvider{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	returned := make(chan struct{})
	go func() {
		loadProvider(map[string]P.Provider{"blocking": provider})
		close(returned)
	}()

	select {
	case <-provider.started:
	case <-time.After(time.Second):
		t.Fatal("provider initialization did not start")
	}

	select {
	case <-returned:
		close(provider.release)
	case <-time.After(100 * time.Millisecond):
		close(provider.release)
		<-returned
		t.Fatal("config apply waited for provider initialization")
	}
}
