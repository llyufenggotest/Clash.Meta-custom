package vless

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/gofrs/uuid/v5"
)

// blackstoneState is per Client, never persisted or shared between identities.
// H is opaque protocol data, not a key for any locally computed HMAC.
type blackstoneState struct {
	extension bool
	mu        sync.RWMutex
	h         []byte
}

func blackstoneCompactUUID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// NewClientWithBlackstoneOptions preserves NewClient behavior unless the exact
// #blackstone selector is present. E/H alone never select a private wire format.
// E and H are independent; this integration requires nonempty valid H to avoid
// silently sending an unauthenticated private request. Errors never echo H.
func NewClientWithBlackstoneOptions(id string, addons *Addons, isX365, e bool, h string) (*Client, error) {
	clean, mode, err := parsePrivateUUID(id)
	if err != nil {
		return nil, err
	}
	if mode != ModeBlackstone {
		return NewClient(id, addons, isX365)
	}
	if isX365 {
		return nil, fmt.Errorf("Blackstone: X365 cannot be combined")
	}
	if h == "" {
		return nil, fmt.Errorf("Blackstone: H is required")
	}
	decoded, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("Blackstone: H must be valid hexadecimal")
	}
	raw, _ := hex.DecodeString(strings.ReplaceAll(clean, "-", ""))
	var key uuid.UUID
	copy(key[:], raw)
	return &Client{uuid: key, Addons: addons, mode: mode, blackstone: &blackstoneState{extension: e, h: decoded}}, nil
}

func (s *blackstoneState) snapshot() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.h...)
}

func (s *blackstoneState) replace(h []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h = append([]byte(nil), h...)
}
