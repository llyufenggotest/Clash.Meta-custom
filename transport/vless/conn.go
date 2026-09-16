package vless

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/transport/vless/vision"

	"github.com/gofrs/uuid/v5"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	N.ExtendedConn
	dst      *DstAddr
	id       uuid.UUID
	addons   *Addons
	received bool
	sent     bool
	isX365   bool // ✨新增
}

func (vc *Conn) Read(b []byte) (int, error) {
	if !vc.received {
		if err := vc.recvResponse(); err != nil {
			return 0, err
		}
		vc.received = true
	}
	return vc.ExtendedConn.Read(b)
}

func (vc *Conn) ReadBuffer(buffer *buf.Buffer) error {
	if !vc.received {
		if err := vc.recvResponse(); err != nil {
			return err
		}
		vc.received = true
	}
	return vc.ExtendedConn.ReadBuffer(buffer)
}

func (vc *Conn) Write(p []byte) (int, error) {
	if !vc.sent {
		if err := vc.sendRequest(p); err != nil {
			return 0, err
		}
		vc.sent = true
		return len(p), nil
	}

	return vc.ExtendedConn.Write(p)
}

func (vc *Conn) WriteBuffer(buffer *buf.Buffer) error {
	if !vc.sent {
		if err := vc.sendRequest(buffer.Bytes()); err != nil {
			return err
		}
		vc.sent = true
		return nil
	}

	return vc.ExtendedConn.WriteBuffer(buffer)
}

func (vc *Conn) sendRequest(p []byte) (err error) {
	// ✨ X365 魔改发包逻辑注入
	if vc.isX365 {
		requestLen := 5  // "X365" + 0x01
		requestLen += 1  // command
		requestLen += 16 // UUID
		if !vc.dst.Mux {
			requestLen += 2 // port
			requestLen += 1 // atyp
			requestLen += len(vc.dst.Addr)
		}
		requestLen += len(p)

		buffer := buf.NewSize(requestLen)
		defer buffer.Release()

		buf.Must(buf.Error(buffer.Write([]byte{'X', '3', '6', '5', 0x01})))

		if vc.dst.Mux {
			buf.Must(buffer.WriteByte(CommandMux))
		} else {
			if vc.dst.UDP {
				buf.Must(buffer.WriteByte(CommandUDP))
			} else {
				buf.Must(buffer.WriteByte(CommandTCP))
			}
		}

		buf.Must(buf.Error(buffer.Write(vc.id.Bytes())))

		if !vc.dst.Mux {
			binary.BigEndian.PutUint16(buffer.Extend(2), vc.dst.Port)
			buf.Must(
				buffer.WriteByte(vc.dst.AddrType),
				buf.Error(buffer.Write(vc.dst.Addr)),
			)
		}
		buf.Must(buf.Error(buffer.Write(p)))
		_, err = vc.ExtendedConn.Write(buffer.Bytes())
		return
	}

	// 官方原版发包逻辑
	var addonsBytes []byte
	if vc.addons != nil {
		addonsBytes, err = proto.Marshal(vc.addons)
		if err != nil {
			return
		}
	}

	requestLen := 1  // protocol version
	requestLen += 16 // UUID
	requestLen += 1  // addons length
	requestLen += len(addonsBytes)
	requestLen += 1 // command
	if !vc.dst.Mux {
		requestLen += 2 // port
		requestLen += 1 // addr type
		requestLen += len(vc.dst.Addr)
	}
	requestLen += len(p)

	buffer := buf.NewSize(requestLen)
	defer buffer.Release()

	buf.Must(
		buffer.WriteByte(Version),              // protocol version
		buf.Error(buffer.Write(vc.id.Bytes())), // 16 bytes of uuid
		buffer.WriteByte(byte(len(addonsBytes))),
		buf.Error(buffer.Write(addonsBytes)),
	)

	if vc.dst.Mux {
		buf.Must(buffer.WriteByte(CommandMux))
	} else {
		if vc.dst.UDP {
			buf.Must(buffer.WriteByte(CommandUDP))
		} else {
			buf.Must(buffer.WriteByte(CommandTCP))
		}

		binary.BigEndian.PutUint16(buffer.Extend(2), vc.dst.Port)
		buf.Must(
			buffer.WriteByte(vc.dst.AddrType),
			buf.Error(buffer.Write(vc.dst.Addr)),
		)
	}

	buf.Must(buf.Error(buffer.Write(p)))

	_, err = vc.ExtendedConn.Write(buffer.Bytes())
	return
}

func (vc *Conn) recvResponse() (err error) {
	if vc.isX365 {
		// ✨ 新增：X365 握手返回验证
		var header [5]byte
		_, err = io.ReadFull(vc.ExtendedConn, header[:])
		if err != nil {
			return err
		}
		if header[0] != 'X' || header[1] != '3' || header[2] != '6' || header[3] != '5' {
			return errors.New("invalid x365 response header")
		}
		return nil
	}

	// 官方原版逻辑
	var buffer [2]byte
	_, err = io.ReadFull(vc.ExtendedConn, buffer[:])
	if err != nil {
		return err
	}

	if buffer[0] != Version {
		return errors.New("unexpected response version")
	}

	length := int64(buffer[1])
	if length != 0 { // addon data length > 0
		io.CopyN(io.Discard, vc.ExtendedConn, length) // just discard
	}

	return
}

func (vc *Conn) Upstream() any {
	return vc.ExtendedConn
}

func (vc *Conn) ReaderReplaceable() bool {
	return vc.received
}

func (vc *Conn) WriterReplaceable() bool {
	return vc.sent
}

func (vc *Conn) NeedHandshake() bool {
	return !vc.sent
}

// newConn return a Conn instance
func newConn(conn net.Conn, client *Client, dst *DstAddr) (net.Conn, error) {
	c := &Conn{
		ExtendedConn: N.NewExtendedConn(conn),
		id:           client.uuid,
		addons:       client.Addons,
		dst:          dst,
		isX365:       client.IsX365, // ✨赋值
	}

	if client.Addons != nil {
		switch client.Addons.Flow {
		case XRV:
			visionConn, err := vision.NewConn(c, conn, c.id)
			if err != nil {
				return nil, err
			}
			return visionConn, nil
		}
	}

	return c, nil
}
