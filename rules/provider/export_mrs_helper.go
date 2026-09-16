package provider

import (
	P "github.com/metacubex/mihomo/constant/provider"
)

// ParseMrsForTest exposes the MRS load path to tests in other packages. The
// production entry point is rulesParse, which is unexported.
func ParseMrsForTest(buf []byte, behavior P.RuleBehavior) (interface {
	Count() int
}, error) {
	return rulesParse(buf, newStrategy(behavior, nil), P.MrsRule)
}
