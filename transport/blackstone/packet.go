package blackstone

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"

	M "github.com/metacubex/sing/common/metadata"
)

// addressBytes validates before invoking the serializer (which accepts invalid
// empty destinations and silently narrows overlong domain lengths).
func addressBytes(addr net.Addr, uot bool) ([]byte, error) {
	if addr == nil {
		return nil, errors.New("blackstone: missing address")
	}
	destination := M.SocksaddrFromNet(addr)
	if destination.Addr.IsValid() {
		destination.Addr = destination.Addr.Unmap()
	}
	if destination.IsFqdn() {
		if len(destination.Fqdn) > 255 || len(destination.Fqdn) == 0 {
			return nil, errors.New("blackstone: invalid domain length")
		}
	} else if !destination.Addr.IsValid() {
		return nil, errors.New("blackstone: invalid address")
	}
	var b bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&b, destination); err != nil {
		return nil, err
	}
	result := b.Bytes()
	if uot {
		switch result[0] {
		case 1:
			result[0] = 0
		case 4:
			result[0] = 1
		case 3:
			result[0] = 2
		}
	}
	return result, nil
}

// PacketConn retains its construction-time auth snapshot, while successful
// downlink packets publish material for subsequently constructed connections.
type PacketConn struct {
	net.PacketConn
	client          *Client
	auth            []byte
	remote          net.Addr
	readMu, writeMu sync.Mutex
}

func (c *Client) PacketConn(conn net.PacketConn, remote net.Addr) *PacketConn {
	return &PacketConn{PacketConn: conn, client: c, auth: c.snapshot(), remote: remote}
}
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	address, err := addressBytes(addr, false)
	if err != nil {
		return 0, err
	}
	// 65507 is the maximum portable IPv4 UDP payload, including our framing.
	if 161+len(c.auth)+len(address)+len(p) > 65507 {
		return 0, errors.New("blackstone: UDP datagram too large")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	header, stream, err := c.client.uplink(c.auth, c.client.udpFake)
	if err != nil {
		return 0, err
	}
	plain := append(address, p...)
	ct := make([]byte, len(plain))
	stream.XORKeyStream(ct, plain)
	packet := append(header, ct...)
	n, err := c.PacketConn.WriteTo(packet, c.remote)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	packet := make([]byte, 65536)
	n, _, err := c.PacketConn.ReadFrom(packet)
	if err != nil {
		return 0, nil, err
	}
	if n < 0 || n > len(packet) {
		return 0, nil, errors.New("blackstone: invalid packet read length")
	}
	reader := bytes.NewReader(packet[:n])
	stream, auth, err := c.client.downlink(reader)
	if err != nil {
		return 0, nil, err
	}
	plain := make([]byte, reader.Len())
	if _, err = io.ReadFull(reader, plain); err != nil {
		return 0, nil, err
	}
	stream.XORKeyStream(plain, plain)
	payload := bytes.NewReader(plain)
	source, err := M.SocksaddrSerializer.ReadAddrPort(payload)
	if err != nil {
		return 0, nil, err
	}
	if !source.IsValid() {
		return 0, nil, errors.New("blackstone: invalid packet source")
	}
	// Publish only after the full framing and logical source have been validated.
	c.client.publish(auth)
	count := copy(p, plain[len(plain)-payload.Len():])
	if count < payload.Len() {
		return count, source, io.ErrShortBuffer
	}
	return count, source, nil
}
