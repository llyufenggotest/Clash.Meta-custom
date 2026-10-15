package outbound

import "testing"

func TestBlackstoneAdapterRejectsRawSelectorWhitespace(t *testing.T) {
	const id = "00112233-4455-6677-8899-aabbccddeeff"
	for _, raw := range []string{id + "#blackstone ", " " + id + "#blackstone", id + "#blackstone\n", "\t" + id + "#blackstone", id + "#blackstone\u3000"} {
		v, err := NewVless(VlessOption{UUID: raw, E: true, H: "aabb"})
		if v != nil {
			_ = v.Close()
		}
		if err == nil {
			t.Errorf("non-exact synthetic selector accepted")
		}
	}
}

func TestBlackstoneExactRepairPreservesLegacyTrim(t *testing.T) {
	const id = "00112233-4455-6677-8899-aabbccddeeff"
	for _, raw := range []string{" " + id + " \n", " " + id + "#juzi \n", " " + id + "#x365 \n"} {
		v, err := NewVless(VlessOption{UUID: raw})
		if err != nil {
			t.Fatal("legacy UUID trim changed")
		}
		_ = v.Close()
	}
	for _, raw := range []string{id + "#blackstone", "00112233445566778899aabbccddeeff#blackstone"} {
		v, err := NewVless(VlessOption{UUID: raw, E: true, H: "aabb"})
		if err != nil {
			t.Fatal("exact private selector rejected")
		}
		_ = v.Close()
	}
}
