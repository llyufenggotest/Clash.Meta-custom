package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/oppa"
	"github.com/metacubex/mihomo/transport/vmess"
)

type Oppa struct {
	*Base
	option *OppaOption
}

type OppaOption struct {
	BasicOption
	Name           string `proxy:"name"`
	Server         string `proxy:"server"`
	Port           int    `proxy:"port"`
	Password       string `proxy:"password"`
	SNI            string `proxy:"sni,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify string `proxy:"name-cert-verify,omitempty"`
	Fingerprint    string `proxy:"fingerprint,omitempty"`
	UDP            bool   `proxy:"udp,omitempty"`
	PreConnect     int    `proxy:"pre-connect,omitempty"`
}

func NewOppa(option OppaOption) (*Oppa, error) {
	if len([]byte(option.Password)) == 0 || len([]byte(option.Password)) > 4096 {
		return nil, fmt.Errorf("Oppa password must contain 1-4096 UTF-8 bytes")
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, fmt.Errorf("invalid Oppa port")
	}
	if option.PreConnect != 0 {
		return nil, fmt.Errorf("Oppa pre-connect is not implemented")
	}
	if option.SNI == "" {
		option.SNI = option.Server
	}
	o := &Oppa{
		Base:   NewBase(BaseOption{Name: option.Name, Addr: net.JoinHostPort(option.Server, strconv.Itoa(option.Port)), Type: constant.Oppa, ProviderName: option.ProviderName, UDP: option.UDP, TFO: option.TFO, MPTCP: option.MPTCP, Interface: option.Interface, RoutingMark: option.RoutingMark, Prefer: option.IPVersion}),
		option: &option,
	}
	o.dialer = option.NewDialer(o.DialOptions())
	return o, nil
}

func (o *Oppa) dialTLS(ctx context.Context) (net.Conn, error) {
	conn, err := o.dialer.DialContext(ctx, "tcp", o.addr)
	if err != nil {
		return nil, err
	}
	conn, err = vmess.StreamTLSConn(ctx, conn, &vmess.TLSConfig{Host: o.option.SNI, SkipCertVerify: o.option.SkipCertVerify, NameCertVerify: o.option.NameCertVerify, FingerPrint: o.option.Fingerprint})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func metadataAddress(metadata *constant.Metadata) oppa.Address {
	address := oppa.Address{Port: metadata.DstPort}
	if metadata.Host != "" {
		address.Domain = metadata.Host
	} else {
		address.IP = metadata.DstIP
	}
	return address
}

func (o *Oppa) DialContext(ctx context.Context, metadata *constant.Metadata) (constant.Conn, error) {
	if metadata.NetWork != constant.TCP {
		if err := o.ResolveUDP(ctx, metadata); err != nil {
			return nil, err
		}
		pc, err := o.ListenPacketContext(ctx, metadata)
		if err != nil {
			return nil, err
		}
		return NewConn(N.NewBindPacketConn(pc, metadata.UDPAddr()), o), nil
	}
	conn, err := o.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	header, err := oppa.BuildTCPHeader(o.option.Password, metadataAddress(metadata))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err = conn.Write(header); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return NewConn(conn, o), nil
}

func (o *Oppa) ListenPacketContext(ctx context.Context, metadata *constant.Metadata) (constant.PacketConn, error) {
	if err := o.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	conn, err := o.dialTLS(ctx)
	if err != nil {
		return nil, err
	}
	header, err := oppa.BuildSessionHeader(o.option.Password, oppa.CommandUDP)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err = conn.Write(header); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return NewPacketConn(oppa.NewPacketConn(conn), o), nil
}

func (o *Oppa) SupportUOT() bool { return false }
func (o *Oppa) ProxyInfo() (info constant.ProxyInfo) {
	info = o.Base.ProxyInfo()
	info.DialerProxy = o.option.DialerProxy
	return
}
func (o *Oppa) Close() error { return nil }

var _ constant.ProxyAdapter = (*Oppa)(nil)
