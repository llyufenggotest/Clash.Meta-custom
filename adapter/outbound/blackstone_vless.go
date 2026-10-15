package outbound

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/common/structure"
)

// Decode the complete existing VLESS schema, not a lossy transport projection.
// The fetched UUID must be bare: never normalize/repair private or mixed markers.
func parseBlackstoneVless(p map[string]any) (xhttpRealConfig, error) {
	fail := func() (xhttpRealConfig, error) {
		return xhttpRealConfig{}, blackstoneSelectionCapability("vless-fields")
	}
	server, ok := p["server"].(string)
	if !ok || strings.TrimSpace(server) == "" || server != strings.TrimSpace(server) {
		return fail()
	}
	id, ok := p["uuid"].(string)
	if !ok || id != strings.TrimSpace(id) || strings.Contains(id, "#") {
		return fail()
	}
	switch len(id) {
	case 32:
		if _, err := hex.DecodeString(id); err != nil {
			return fail()
		}
	case 36:
		if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			return fail()
		}
		if _, err := uuid.FromString(id); err != nil {
			return fail()
		}
	default:
		return fail()
	}
	// Weak typing matches ParseProxy for the remaining schema, but must not
	// coerce an absent/non-boolean E or numeric/invalid H into authentication.
	if _, ok := p["e"].(bool); !ok {
		return fail()
	}
	h, ok := p["h"].(string)
	if !ok || h == "" {
		return fail()
	}
	if _, err := hex.DecodeString(h); err != nil {
		return fail()
	}
	// Reject lossy weak coercion of floats/bools before decoding the schema.
	switch port := p["port"].(type) {
	case int:
		if port < 1 || port > 65535 {
			return fail()
		}
	case string:
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fail()
		}
	default:
		return fail()
	}
	var option VlessOption
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if err := decoder.Decode(p, &option); err != nil {
		return fail()
	}
	if option.Port < 1 || option.Port > 65535 {
		return fail()
	}
	option.UUID = id + "#blackstone"
	return xhttpRealConfig{Name: option.Name, Type: "vless", Server: server, Port: strconv.Itoa(option.Port), UDP: option.UDP, vlessOption: &option}, nil
}

func (h *XHttp) newBlackstoneVless(cfg xhttpRealConfig) (*Vless, error) {
	if cfg.vlessOption == nil {
		return nil, blackstoneSelectionCapability("vless-fields")
	}
	option := *cfg.vlessOption
	// Parent front/API policy owns data routing. Fetched dialer settings cannot
	// bypass it or change its identity; transport TLS/network fields stay intact.
	option.BasicOption = h.option.BasicOption
	option.Name = h.option.Name + "_vless"
	v, err := NewVless(option)
	if err != nil {
		return nil, blackstoneStageError("node-capability", err)
	}
	return v, nil
}
