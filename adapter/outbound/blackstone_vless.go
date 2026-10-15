package outbound

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/gofrs/uuid/v5"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/vless"
	vmessSing "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing-vmess/packetaddr"
	M "github.com/metacubex/sing/common/metadata"
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
	// Dynamic exact input must not rely on legacy weak coercion or flow truncation.
	for _, key := range []string{"network", "flow"} {
		if value, present := p[key]; present {
			if _, ok := value.(string); !ok {
				return fail()
			}
		}
	}
	var option VlessOption
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if err := decoder.Decode(p, &option); err != nil {
		return fail()
	}
	if option.Port < 1 || option.Port > 65535 {
		return fail()
	}
	if err := validateBlackstoneVlessSemantics(option); err != nil {
		return xhttpRealConfig{}, err
	}
	option.UUID = id + "#blackstone"
	return xhttpRealConfig{Name: option.Name, Type: "vless", Server: server, Port: strconv.Itoa(option.Port), UDP: option.UDP, vlessOption: &option}, nil
}

func (h *XHttp) newBlackstoneVless(cfg xhttpRealConfig) (*Vless, error) {
	if cfg.vlessOption == nil {
		return nil, blackstoneSelectionCapability("vless-fields")
	}
	option := *cfg.vlessOption
	if err := validateBlackstoneVlessSemantics(option); err != nil {
		return nil, err
	}
	// Parent front/API policy owns data routing. Fetched dialer settings cannot
	// bypass it or change its identity; transport TLS/network fields stay intact.
	option.BasicOption = h.option.BasicOption
	option.Name = h.option.Name + "_vless"
	v, err := NewVless(option)
	if err != nil {
		return nil, blackstoneVlessError("node-capability", err)
	}
	return v, nil
}

// Only actual production transport branches are admitted. Standard NewVless
// intentionally retains its historical TCP fallback and flow normalization.
func validateBlackstoneVlessSemantics(option VlessOption) error {
	switch option.Network {
	case "", "tcp", "ws", "http", "h2", "grpc", "xhttp":
	default:
		return blackstoneVlessError("node-capability", nil)
	}
	if option.Flow != "" && option.Flow != vless.XRV {
		return blackstoneVlessError("node-capability", nil)
	}
	return nil
}

// Keep only closed-vocabulary diagnostics and lifecycle identities, never the
// fetched endpoint or raw cause. In particular there is no private Unwrap/As.
type blackstoneVlessFailure struct {
	stage, class               string
	canceled, deadline, closed bool
}

func (e *blackstoneVlessFailure) Error() string {
	return "blackstone vless stage=" + e.stage + " class=" + e.class
}
func (e *blackstoneVlessFailure) Is(target error) bool {
	return (target == context.Canceled && e.canceled) ||
		(target == context.DeadlineExceeded && e.deadline) ||
		(target == net.ErrClosed && e.closed)
}
func blackstoneVlessError(stage string, err error) error {
	e := &blackstoneVlessFailure{stage: stage, class: "failure",
		canceled: errors.Is(err, context.Canceled), deadline: errors.Is(err, context.DeadlineExceeded), closed: errors.Is(err, net.ErrClosed)}
	switch {
	case e.canceled:
		e.class = "cancellation"
	case e.deadline:
		e.class = "deadline"
	case e.closed:
		e.class = "closed"
	}
	return e
}

// Use the same production stream/packet machinery, but intercept its typed
// error before legacy Vless public methods flatten it into private text.
func (v *Vless) blackstoneStream(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	c, err := v.dialContext(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := v.StreamConnContext(ctx, c, metadata)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return stream, nil
}
func (v *Vless) dialBlackstoneContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := v.blackstoneStream(ctx, metadata)
	if err != nil {
		return nil, blackstoneVlessError("data-tcp", err)
	}
	return NewConn(c, v), nil
}
func (v *Vless) listenBlackstoneContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := v.ResolveUDP(ctx, metadata); err != nil {
		return nil, blackstoneVlessError("data-udp", err)
	}
	c, err := v.blackstoneStream(ctx, metadata)
	if err != nil {
		return nil, blackstoneVlessError("data-udp", err)
	}
	if v.option.XUDP {
		var globalID [8]byte
		if metadata.SourceValid() {
			globalID = utils.GlobalID(metadata.SourceAddress())
		}
		return NewPacketConn(N.NewThreadSafePacketConn(vmessSing.NewXUDPConn(c, globalID, M.SocksaddrFromNet(metadata.UDPAddr()))), v), nil
	}
	if v.option.PacketAddr {
		return NewPacketConn(N.NewThreadSafePacketConn(packetaddr.NewConn(v.client.PacketConn(c, metadata.UDPAddr()), M.SocksaddrFromNet(metadata.UDPAddr()))), v), nil
	}
	return NewPacketConn(N.NewThreadSafePacketConn(v.client.PacketConn(c, metadata.UDPAddr())), v), nil
}
