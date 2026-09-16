package executor

import "testing"

func TestPreflightRuleProvidersAcceptsEmptySet(t *testing.T) {
	if err := preflightRuleProviders(nil, false); err != nil {
		t.Fatal(err)
	}
}
