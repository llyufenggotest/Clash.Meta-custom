package vless

import (
	"fmt"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/utils"

	"github.com/gofrs/uuid/v5"
)

const (
	XRO = "xtls-rprx-origin"
	XRD = "xtls-rprx-direct"
	XRS = "xtls-rprx-splice"
	XRV = "xtls-rprx-vision"

	Version byte = 0 // protocol version. preview version is 0
)

// Command types
const (
	CommandTCP byte = 1
	CommandUDP byte = 2
	CommandMux byte = 3
)

// Addr types
const (
	AtypIPv4       byte = 1
	AtypDomainName byte = 2
	AtypIPv6       byte = 3
)

// DstAddr store destination address
type DstAddr struct {
	UDP      bool
	AddrType byte
	Addr     []byte
	Port     uint16
	Mux      bool // currently used for XUDP only
}

// Client is vless connection generator
type Client struct {
	uuid   uuid.UUID
	Addons *Addons
	IsX365 bool // ✨魔改新增
	mode   PrivateMode
}

// StreamConn return a Conn with net.Conn and DstAddr
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	if c.mode == ModePure {
		return c.dialPure(conn, dst)
	}
	return newConn(conn, c, dst)
}

func (c *Client) PacketConn(conn net.Conn, rAddr net.Addr) net.PacketConn {
	if c.mode == ModePure {
		return &purePacketReject{}
	}
	return &PacketConn{conn, rAddr}
}

type purePacketReject struct{}

func (*purePacketReject) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, fmt.Errorf("Pure: UDP/XUDP unsupported")
}
func (*purePacketReject) WriteTo([]byte, net.Addr) (int, error) {
	return 0, fmt.Errorf("Pure: UDP/XUDP unsupported")
}
func (*purePacketReject) Close() error                     { return nil }
func (*purePacketReject) LocalAddr() net.Addr              { return nil }
func (*purePacketReject) SetDeadline(time.Time) error      { return nil }
func (*purePacketReject) SetReadDeadline(time.Time) error  { return nil }
func (*purePacketReject) SetWriteDeadline(time.Time) error { return nil }

// NewClient return Client instance
func NewClient(uuidStr string, addons *Addons, isX365 bool) (*Client, error) { // ✨修复：这里加上了 isX365 bool
	cleanID, mode, err := parsePrivateUUID(uuidStr)
	if err != nil {
		return nil, err
	}
	if mode == ModeX365 {
		isX365 = true
	}
	if mode == ModePure {
		key, _, err := pureIdentity(uuidStr)
		if err != nil {
			return nil, err
		}
		return &Client{uuid: key, Addons: addons, mode: mode}, nil
	}
	uid := utils.UUIDMap(cleanID)
	return &Client{uuid: uid, Addons: addons, IsX365: isX365, mode: mode}, nil
}
