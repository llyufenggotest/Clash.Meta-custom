package executor

import (
	"fmt"
	"sort"

	P "github.com/metacubex/mihomo/constant/provider"
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
		provider := providers[name]
		var err error
		if localOnly {
			if initial, ok := provider.(interface{ InitialLocal() error }); ok {
				err = initial.InitialLocal()
			} else {
				err = fmt.Errorf("provider does not support local-only initialization")
			}
		} else {
			err = provider.Initial()
		}
		if err == nil {
			if validator, ok := provider.(interface{ ValidateForExtension() error }); ok {
				err = validator.ValidateForExtension()
			}
		}
		if err != nil {
			closeRuleProviders(providers)
			return fmt.Errorf("rule provider %q preflight failed: %w", name, err)
		}
	}
	return nil
}

func closeRuleProviders(providers map[string]P.RuleProvider) {
	for _, provider := range providers {
		if closer, ok := provider.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}
