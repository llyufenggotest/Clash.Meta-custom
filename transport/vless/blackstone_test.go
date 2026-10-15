package vless

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const blackstoneTestID = "00112233-4455-6677-8899-aabbccddeeff"

// A selector must never silently become UUIDMap authentication material.
// This test deliberately uses only the pre-existing API for a real behavioral RED.
func TestBlackstoneSelectorRequiresAuthentication(t *testing.T) {
	for _, id := range []string{blackstoneTestID + "#blackstone", blackstoneTestID + "#BlackStone", blackstoneTestID + "#blackstone#blackstone", blackstoneTestID + "#blackstone#juzi", blackstoneTestID + "#pure#blackstone"} {
		if _, err := NewClient(id, nil, false); err == nil {
			t.Errorf("accepted unconfigured or invalid Blackstone selector %q", id)
		}
	}
}

// Literal fixtures freeze the existing formats independently of the new code.
func TestBlackstoneLegacyWireUnchanged(t *testing.T) {
	for _, tc := range []struct{ suffix, golden string }{
		{"", "0000112233445566778899aabbccddeeff000101bb0101020304706179"},
		{"#juzi", "0000112233445566778899aabbccddeeff8c2cdb151f9c8f59000101bb0101020304706179"},
		{"#x365", "58333635010100112233445566778899aabbccddeeff01bb0101020304706179"},
		{"#pure", "a100112233445566778899aabbccddeeff000101bb0101020304706179"},
	} {
		t.Run(tc.suffix, func(t *testing.T) {
			c, err := NewClient(blackstoneTestID+tc.suffix, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			raw := &juziPureMemoryConn{}
			conn, err := c.StreamConn(raw, &DstAddr{Port: 443, AddrType: AtypIPv4, Addr: []byte{1, 2, 3, 4}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = conn.Write([]byte("pay")); err != nil {
				t.Fatal(err)
			}
			got := bytes.Join(raw.writes, nil)
			if hex.EncodeToString(got) != tc.golden {
				t.Fatalf("wire=%x want=%s", got, tc.golden)
			}
		})
	}
}
