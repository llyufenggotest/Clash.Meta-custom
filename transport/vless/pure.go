package vless

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
)

// PrivateMode keeps private wire formats mutually exclusive.
type PrivateMode uint8

const (
	ModeStandard PrivateMode = iota
	ModeX365
	ModeJuzi
	ModePure
)

func parsePrivateUUID(value string) (id string, mode PrivateMode, err error) {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "#pure") {
		if !strings.HasSuffix(lower, "#pure") {
			return "", ModePure, fmt.Errorf("Pure: invalid or mixed suffix")
		}
		id = value[:len(value)-len("#pure")]
		if !canonicalUUID(id) {
			return "", ModePure, fmt.Errorf("Pure: canonical UUID required")
		}
		return id, ModePure, nil
	}
	id = value
	if strings.HasSuffix(lower, "#juzi") {
		return value[:len(value)-len("#juzi")], ModeJuzi, nil
	}
	// X365 intentionally remains exact lowercase for compatibility.
	if strings.HasSuffix(value, "#x365") {
		return value[:len(value)-len("#x365")], ModeX365, nil
	}
	return id, ModeStandard, nil
}

func canonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

func pureIdentity(value string) ([16]byte, bool, error) {
	id, mode, err := parsePrivateUUID(value)
	if err != nil {
		return [16]byte{}, mode == ModePure, err
	}
	if mode != ModePure {
		return [16]byte{}, false, nil
	}
	decoded, _ := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	var key [16]byte
	copy(key[:], decoded)
	return key, true, nil
}

func pureHeader(key [16]byte, dst *DstAddr) ([]byte, error) {
	if dst == nil || dst.Port == 0 || dst.UDP || dst.Mux {
		return nil, fmt.Errorf("Pure: TCP-only destination required")
	}
	if dst.AddrType == AtypIPv6 {
		return nil, fmt.Errorf("Pure: IPv6 destination unsupported")
	}
	if dst.AddrType != AtypIPv4 && dst.AddrType != AtypDomainName {
		return nil, fmt.Errorf("Pure: invalid destination type")
	}
	if dst.AddrType == AtypIPv4 && len(dst.Addr) != 4 {
		return nil, fmt.Errorf("Pure: invalid IPv4 destination")
	}
	if dst.AddrType == AtypDomainName {
		if len(dst.Addr) < 2 || int(dst.Addr[0]) != len(dst.Addr)-1 {
			return nil, fmt.Errorf("Pure: invalid destination domain")
		}
	}
	b := append([]byte{0xa1}, key[:]...)
	b = append(b, 0, CommandTCP, byte(dst.Port>>8), byte(dst.Port))
	b = append(b, dst.AddrType)
	return append(b, dst.Addr...), nil
}

type pureConn struct {
	net.Conn
	ready       bool
	responseErr error
}

func (c *pureConn) NeedAdditionalReadDeadline() bool { return true }
func (c *pureConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.responseErr != nil {
		return 0, c.responseErr
	}
	if !c.ready {
		var header [2]byte
		_, err := io.ReadFull(c.Conn, header[:])
		if err == nil && header != [2]byte{0xa1, 0} {
			err = fmt.Errorf("Pure response prefix invalid")
		}
		if err != nil {
			c.responseErr = err
			return 0, err
		}
		c.ready = true
	}
	return c.Conn.Read(p)
}

func (c *Client) dialPure(conn net.Conn, dst *DstAddr) (net.Conn, error) {
	wire, err := pureHeader(c.uuid, dst)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	n, err := conn.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &pureConn{Conn: conn}, nil
}
