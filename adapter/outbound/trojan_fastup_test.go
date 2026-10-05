package outbound

import (
	"crypto/md5"
	"encoding/hex"
	"testing"

	transport "github.com/metacubex/mihomo/transport/trojan"
)

func TestFastupTrojanPasswordDerivation(t *testing.T) {
	const password = "synthetic-password#fastup"
	const mpw = "rotated-mpw"

	derived, fastup := deriveTrojanPassword(password, mpw)
	if !fastup {
		t.Fatal("Fastup suffix was not detected")
	}
	digest := md5.Sum([]byte("synthetic-password" + mpw))
	if derived != hex.EncodeToString(digest[:]) {
		t.Fatal("explicit mpw was not used")
	}
	if transport.Key(derived) == transport.Key(password) {
		t.Fatal("Fastup key did not change")
	}
}

func TestStandardTrojanIgnoresMpw(t *testing.T) {
	const password = "ordinary-password"
	derived, fastup := deriveTrojanPassword(password, "must-be-ignored")
	if fastup || derived != password {
		t.Fatal("standard Trojan behavior changed")
	}
}

func TestFastupTrojanOnlyMatchesExactSuffix(t *testing.T) {
	const password = "ordinary#fastup-not-a-suffix"
	derived, fastup := deriveTrojanPassword(password, "ignored")
	if fastup || derived != password {
		t.Fatal("non-suffix marker enabled Fastup")
	}
}
