package provider

import P "github.com/metacubex/mihomo/constant/provider"

func reuseActiveStrategy(name string, behavior P.RuleBehavior, format P.RuleFormat, content ruleContentDigest) (loadedRuleStrategy, bool) {
	if tunnel == nil || (behavior != P.Domain && behavior != P.IPCIDR) {
		return loadedRuleStrategy{}, false
	}
	providers, release := tunnel.AcquireRuleProviders()
	defer release()
	active, ok := providers[name].(*RuleSetProvider)
	if !ok || active.behavior != behavior || active.format != format {
		return loadedRuleStrategy{}, false
	}
	active.readyMu.RLock()
	defer active.readyMu.RUnlock()
	if active.readyDigest == "" || active.readyContent != content {
		return loadedRuleStrategy{}, false
	}
	// Only finished domain/IP matchers are shared; every update builds a new one.
	return loadedRuleStrategy{strategy: active.strategy, digest: active.readyDigest, content: content}, true
}
