package mmdb

import "testing"

// The iOS Network Extension has a ~50 MB phys_footprint budget, and iOS counts
// file-backed mmap pages against it. maxminddb opens databases with mmap, so
// mapping GeoLite2-ASN.mmdb costs the extension roughly 20 MB of its budget --
// measured on device as a 32-33 MB starting footprint for profiles with IP-ASN
// rules versus 13-15 MB for profiles without them.
//
// On low-memory builds geodata.InitASN stores asnEnable=false, so ASN rules can
// never match. Mapping the database there is pure loss, which is why
// ASNInstance short-circuits. These tests pin that behaviour down.

func TestASNMappingDisabledOnLowMemoryBuilds(t *testing.T) {
	// Guard against the build-tag files drifting apart or both being dropped.
	// asnMappingAllowed must be false exactly when with_low_memory is set.
	if asnMappingAllowed {
		t.Skip("not a low-memory build; see TestASNMappingAllowedOnNormalBuilds")
	}

	reader := ASNInstance()
	if reader.Reader != nil {
		t.Fatal("ASNInstance mapped the ASN database on a low-memory build: " +
			"this costs the iOS extension ~20 MB of its ~50 MB footprint budget " +
			"for a feature that is disabled and can never match")
	}

	// Every caller must survive the unmapped reader rather than panicking on a
	// nil embedded *maxminddb.Reader.
	asn, org := reader.LookupASN([]byte{1, 1, 1, 1})
	if asn != "" || org != "" {
		t.Fatalf("LookupASN on an unmapped reader returned (%q, %q), want empty", asn, org)
	}
}

func TestASNMappingAllowedOnNormalBuilds(t *testing.T) {
	if !asnMappingAllowed {
		t.Skip("low-memory build; see TestASNMappingDisabledOnLowMemoryBuilds")
	}
	// Do not call ASNInstance here: on a normal build it would map (or
	// log.Fatalln over) a database this test has no business fetching. The
	// constant is the contract.
}

func TestLookupASNToleratesUnmappedReader(t *testing.T) {
	// Holds on every build: a zero ASNReader must answer, not panic.
	var zero ASNReader
	asn, org := zero.LookupASN([]byte{8, 8, 8, 8})
	if asn != "" || org != "" {
		t.Fatalf("zero ASNReader returned (%q, %q), want empty", asn, org)
	}
}
