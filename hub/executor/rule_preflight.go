package executor

import (
	"fmt"
	P "github.com/metacubex/mihomo/constant/provider"
	"sort"
)

// Preflight is synchronous and sequential: never run with empty providers and
// never multiply matcher construction peaks. Low-memory startup is local-only
// because first network fetches can depend on the not-yet-started TUN.
func preflightRuleProviders(providers map[string]P.RuleProvider, localOnly bool) error {
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pv := providers[name]
		var err error
		if localOnly {
			if local, ok := pv.(interface{ InitialLocal() error }); ok {
				err = local.InitialLocal()
			} else if pv.VehicleType() == P.Inline {
				err = pv.Initial()
			} else {
				err = fmt.Errorf("provider does not support local preflight; prepare in app")
			}
		} else {
			err = pv.Initial()
			if err == nil {
				if prepared, ok := pv.(interface{ ValidateForExtension() error }); ok {
					err = prepared.ValidateForExtension()
				}
			}
		}
		if err != nil {
			for _, p := range providers {
				if closer, ok := p.(interface{ Close() error }); ok {
					_ = closer.Close()
				}
			}
			return fmt.Errorf("rule provider %q preflight failed: %w", name, err)
		}
	}
	return nil
}
