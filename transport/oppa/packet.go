package oppa

import (
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type PacketConn struct {
	net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewPacketConn(conn net.Conn) *PacketConn {
	return &PacketConn{Conn: conn}
}

func (c *PacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	source, destination, payload, err := DecodeUDPFrame(c.Conn)
	_ = source
	if err != nil {
		return 0, nil, err
	}
	if len(payload) > len(buffer) {
		return 0, nil, io.ErrShortBuffer
	}
	n := copy(buffer, payload)
	return n, destination.UDPAddr(), nil
}

func (c *PacketConn) WriteTo(payload []byte, address net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	destination, err := AddressFromNet(address)
	if err != nil {
		return 0, err
	}
	frame, err := EncodeUDPFrame(Address{IP: netip.IPv4Unspecified()}, destination, payload)
	if err != nil {
		return 0, err
	}
	if _, err = c.Conn.Write(frame); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *PacketConn) LocalAddr() net.Addr                { return c.Conn.LocalAddr() }
func (c *PacketConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *PacketConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *PacketConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

func AddressFromNet(address net.Addr) (Address, error) {
	switch value := address.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(value.IP)
		if !ok {
			return Address{}, &net.AddrError{Err: "invalid IP", Addr: value.String()}
		}
		return Address{IP: ip.Unmap(), Port: uint16(value.Port)}, nil
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(value.IP)
		if !ok {
			return Address{}, &net.AddrError{Err: "invalid IP", Addr: value.String()}
		}
		return Address{IP: ip.Unmap(), Port: uint16(value.Port)}, nil
	default:
		host, port, err := net.SplitHostPort(address.String())
		if err != nil {
			return Address{}, err
		}
		parsedPort, err := net.LookupPort("udp", port)
		if err != nil {
			return Address{}, err
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			return Address{IP: ip.Unmap(), Port: uint16(parsedPort)}, nil
		}
		return Address{Domain: host, Port: uint16(parsedPort)}, nil
	}
}

func (a Address) UDPAddr() net.Addr {
	if a.IP.IsValid() {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.IP, a.Port))
	}
	return domainAddr{network: "udp", address: net.JoinHostPort(a.Domain, strconv.Itoa(int(a.Port)))}
}

type domainAddr struct {
	network string
	address string
}

func (a domainAddr) Network() string { return a.network }
func (a domainAddr) String() string  { return a.address }
