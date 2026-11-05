package artifact

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/easytier/easytier/easytier-go/proto"
)

func TestEmbeddedProvenance(t *testing.T) {
	if got := fmt.Sprintf("%x", sha256.Sum256(Core())); got != SHA256 {
		t.Fatalf("embedded WASM SHA256=%s want %s", got, SHA256)
	}
	if Commit != proto.EasyTierCommit {
		t.Fatalf("WASM commit %s != protobuf commit %s", Commit, proto.EasyTierCommit)
	}
}
