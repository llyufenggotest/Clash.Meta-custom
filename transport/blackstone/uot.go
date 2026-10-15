package blackstone

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

// The pinned sing UOT uses the verified 0/1/2 datagram address mapping,
// but its EncodeRequest uses SOCKS ATYP instead of this native client's UOT
// mapping. Reuse AddrParser, not NewLazyConn's incompatible request encoder.
func UOTDestination(version int) (M.Socksaddr, error) {
	if version < 0 || version > 2 {
		return M.Socksaddr{}, errors.New("blackstone: unsupported UOT version")
	}
	return uot.RequestDestination(uint8(version)), nil
}

type UOTConn struct {
	net.Conn
	initial           []byte
	first             bool
	readMu, writeMu   sync.Mutex
	readErr, writeErr error
}

func NewUOT(conn net.Conn, version int, destination net.Addr) (*UOTConn, error) {
	if _, err := UOTDestination(version); err != nil {
		return nil, err
	}
	initial, err := addressBytes(destination, true)
	if err != nil {
		return nil, err
	}
	return &UOTConn{Conn: conn, initial: initial, first: version != 1}, nil
}
func (c *UOTConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, errors.New("blackstone: UOT payload too large")
	}
	address, err := addressBytes(addr, true)
	if err != nil {
		return 0, err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	var frame []byte
	if c.first {
		frame = append([]byte{0}, c.initial...)
	}
	frame = append(frame, address...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(p)))
	frame = append(frame, p...)

	n, err := c.Conn.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.writeErr = err
		_ = c.Conn.Close()
		return 0, err
	}
	c.first = false
	return len(p), nil
}
func (c *UOTConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	source, err := uot.AddrParser.ReadAddrPort(c.Conn)
	if err != nil {
		c.readErr = err
		return 0, nil, err
	}
	if !source.IsValid() {
		c.readErr = errors.New("blackstone: invalid UOT source")
		return 0, nil, c.readErr
	}
	var size [2]byte
	if _, err = io.ReadFull(c.Conn, size[:]); err != nil {
		c.readErr = err
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	n := min(length, len(p))
	if _, err = io.ReadFull(c.Conn, p[:n]); err != nil {
		c.readErr = err
		return 0, nil, err
	}
	if n < length {
		if _, err = io.CopyN(io.Discard, c.Conn, int64(length-n)); err != nil {
			c.readErr = err
			return n, source, err
		}
		return n, source, io.ErrShortBuffer
	}
	return n, source, nil
}
