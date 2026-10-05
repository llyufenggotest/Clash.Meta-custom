package common

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/constant/features"
)

// On low-memory builds geodata.InitASN returns nil while storing asnEnable=false.
// Building an ASN rule anyway produces a rule that can never match but whose
// first Match call mmaps the ~20 MB ASN database -- fatal against the iOS
// extension's ~50 MB phys_footprint budget. NewIPASN must refuse instead.
func TestNewIPASNRefusedWhenASNDisabled(t *testing.T) {
	if !features.WithLowMemory {
		t.Skip("ASN is enabled on normal builds; nothing to refuse")
	}

	// Precondition: InitASN succeeds but leaves the feature off. If this ever
	// changes, the guard below is testing the wrong thing.
	if err := geodata.InitASN(); err != nil {
		t.Fatalf("InitASN on a low-memory build returned %v, want nil", err)
	}
	if geodata.ASNEnable() {
		t.Fatal("ASNEnable() is true on a low-memory build; " +
			"the premise of the NewIPASN guard no longer holds")
	}

	rule, err := NewIPASN("13335", "DIRECT", false, false)
	if err == nil {
		t.Fatal("NewIPASN built an ASN rule while the ASN database is disabled: " +
			"the rule cannot match, and its first Match would mmap ~20 MB")
	}
	if rule != nil {
		t.Fatalf("NewIPASN returned a non-nil rule alongside error %v", err)
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("error %q does not explain that ASN is disabled", err)
	}
}
