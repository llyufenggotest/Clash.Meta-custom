package oppa

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	CommandTCP byte = 0x01
	CommandUDP byte = 0x02

	maxTokenBytes = 4096
	maxUDPFrame   = 65535
)

type Address struct {
	IP     netip.Addr
	Domain string
	Port   uint16
}

func BuildSessionHeader(token string, command byte) ([]byte, error) {
	if command != CommandTCP && command != CommandUDP {
		return nil, fmt.Errorf("unsupported Oppa command: %d", command)
	}
	if len(token) == 0 || len([]byte(token)) > maxTokenBytes {
		return nil, errors.New("Oppa token must contain 1-4096 UTF-8 bytes")
	}
	header := make([]byte, 0, len(token)+1)
	header = append(header, []byte(token)...)
	header = append(header, command)
	return header, nil
}

func BuildTCPHeader(token string, destination Address) ([]byte, error) {
	header, err := BuildSessionHeader(token, CommandTCP)
	if err != nil {
		return nil, err
	}
	return appendAddress(header, destination)
}

func appendAddress(dst []byte, address Address) ([]byte, error) {
	if address.Domain != "" {
		domain := []byte(address.Domain)
		if len(domain) == 0 || len(domain) > 255 {
			return nil, errors.New("Oppa domain length must be 1-255 bytes")
		}
		dst = append(dst, 0x03, byte(len(domain)))
		dst = append(dst, domain...)
	} else if address.IP.IsValid() {
		if address.IP.Is4() {
			dst = append(dst, 0x01)
			ip := address.IP.As4()
			dst = append(dst, ip[:]...)
		} else {
			dst = append(dst, 0x04)
			ip := address.IP.As16()
			dst = append(dst, ip[:]...)
		}
	} else {
		return nil, errors.New("Oppa address is empty")
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], address.Port)
	return append(dst, port[:]...), nil
}

func readAddress(r io.Reader) (Address, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Address{}, err
	}
	var address Address
	switch atyp[0] {
	case 0x01:
		var raw [4]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return Address{}, err
		}
		address.IP = netip.AddrFrom4(raw)
	case 0x03:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return Address{}, err
		}
		if size[0] == 0 {
			return Address{}, errors.New("empty Oppa domain")
		}
		domain := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return Address{}, err
		}
		address.Domain = string(domain)
	case 0x04:
		var raw [16]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return Address{}, err
		}
		address.IP = netip.AddrFrom16(raw)
	default:
		return Address{}, fmt.Errorf("unsupported Oppa address type: %d", atyp[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Address{}, err
	}
	address.Port = binary.BigEndian.Uint16(port[:])
	return address, nil
}

func EncodeUDPFrame(source, destination Address, payload []byte) ([]byte, error) {
	body, err := appendAddress(nil, source)
	if err != nil {
		return nil, err
	}
	body, err = appendAddress(body, destination)
	if err != nil {
		return nil, err
	}
	body = append(body, payload...)
	if len(body) > maxUDPFrame {
		return nil, errors.New("Oppa UDP frame exceeds 65535 bytes")
	}
	frame := make([]byte, 2, len(body)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(body)))
	return append(frame, body...), nil
}

func DecodeUDPFrame(r io.Reader) (Address, Address, []byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return Address{}, Address{}, nil, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return Address{}, Address{}, nil, err
	}
	reader := &byteReader{data: body}
	source, err := readAddress(reader)
	if err != nil {
		return Address{}, Address{}, nil, err
	}
	destination, err := readAddress(reader)
	if err != nil {
		return Address{}, Address{}, nil, err
	}
	payload := append([]byte(nil), reader.data[reader.offset:]...)
	return source, destination, payload, nil
}

type byteReader struct {
	data   []byte
	offset int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
