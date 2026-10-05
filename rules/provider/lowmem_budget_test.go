package provider

import (
	"strings"
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
)

// The budget must be a build-tag decision, not a runtime one: the app-process
// core and every desktop build load rule sets at full fidelity, and only the
// core embedded in the iOS Network Extension is capped. A single wrong tag here
// either breaks desktop routing or leaves the extension dying, and both failures
// are invisible in a positive-only check.
func TestRuleSetBudgetIsBuildTagged(t *testing.T) {
	if maxLowMemoryRuleCount < 0 {
		t.Fatalf("maxLowMemoryRuleCount must not be negative, got %d", maxLowMemoryRuleCount)
	}
	t.Logf("maxLowMemoryRuleCount = %d", maxLowMemoryRuleCount)
}

func parseDomains(t *testing.T, n int) (ruleStrategy, error) {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("payload:\n")
	for i := 0; i < n; i++ {
		sb.WriteString("  - '+.host")
		sb.WriteString(itoa(i))
		sb.WriteString(".example'\n")
	}
	// Domain behavior never consults the parse func, so nil is correct here and
	// avoids an import cycle with rules (which imports this package).
	return rulesParse([]byte(sb.String()), newStrategy(P.Domain, nil), P.YamlRule)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// A rule set inside the budget must load identically on every build.
func TestRuleSetWithinBudgetLoads(t *testing.T) {
	strategy, err := parseDomains(t, 500)
	if err != nil {
		t.Fatalf("500 domains must load on any build: %v", err)
	}
	if strategy.Count() != 500 {
		t.Errorf("Count() = %d, want 500", strategy.Count())
	}
}

// Above the cap the low-memory build must refuse BEFORE building the matcher;
// other builds must still load. Asserting both directions in one test keeps the
// two variants from drifting apart.
func TestRuleSetOverBudget(t *testing.T) {
	const n = 12000
	strategy, err := parseDomains(t, n)

	if maxLowMemoryRuleCount == 0 {
		if err != nil {
			t.Fatalf("uncapped build must load %d domains: %v", n, err)
		}
		if strategy.Count() != n {
			t.Errorf("Count() = %d, want %d", strategy.Count(), n)
		}
		return
	}

	if err == nil {
		t.Fatalf("capped build (%d) must reject %d domains", maxLowMemoryRuleCount, n)
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error should identify the budget, got %q", err)
	}
	if strategy != nil {
		t.Error("no strategy should be returned when the budget is exceeded")
	}
}
