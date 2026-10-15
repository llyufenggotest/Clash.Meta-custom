// Package blackstone implements Blackstone's private transport, not VLESS XHTTP.
// Its CTR wire is not authenticated encryption; the token is only a matching value.
package blackstone

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

type Config struct{ Password, Cipher, TCPFake, UDPFake string }

// Client belongs to exactly one selected node/configuration generation.
// Never reuse it across a refresh, even if the password appears unchanged.
type Client struct {
	block   cipher.Block
	token   [16]byte
	tcpFake []byte
	udpFake []byte
	mu      sync.Mutex
	auth    []byte
}

func New(config Config) (*Client, error) {
	parts := strings.Split(config.Password, ":")
	if len(parts) < 2 {
		return nil, errors.New("blackstone: password requires auth hex")
	}
	// Bound before decoding: a response auth blob is at most [u8 || 255 bytes].
	// Its contents remain opaque; do not synthesize or normalize a length byte.
	if len(parts[1]) > 512 {
		return nil, errors.New("blackstone: auth blob too large")
	}
	auth, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("blackstone: malformed auth hex")
	}
	prefix, err := hex.DecodeString(config.TCPFake)
	if err != nil || len(prefix) > 128 {
		return nil, errors.New("blackstone: invalid TCP fake prefix")
	}
	udpPrefix, err := hex.DecodeString(config.UDPFake)
	if err != nil || len(udpPrefix) > 128 {
		return nil, errors.New("blackstone: invalid UDP fake prefix")
	}
	keySize := 16
	switch strings.ToUpper(config.Cipher) {
	case "", "AES-128-CTR":
	case "AES-192-CTR":
		keySize = 24
	case "AES-256-CTR":
		keySize = 32
	case "DUMMY":
		return nil, errors.New("blackstone: DUMMY destination serialization unverified; unsupported")
	default:
		return nil, errors.New("blackstone: unsupported cipher")
	}
	var key, last []byte
	for len(key) < keySize {
		sum := md5.Sum(append(append([]byte(nil), last...), []byte(parts[0])...))
		last = sum[:]
		key = append(key, last...)
	}
	block, err := aes.NewCipher(key[:keySize])
	if err != nil {
		return nil, err
	}
	return &Client{block: block, token: md5.Sum([]byte(parts[0] + "do not hack this protocol please")), tcpFake: prefix, udpFake: udpPrefix, auth: auth}, nil
}
func (c *Client) snapshot() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.auth...)
}
func (c *Client) publish(auth []byte) {
	c.mu.Lock()
	c.auth = append([]byte(nil), auth...)
	c.mu.Unlock()
}
func (c *Client) uplink(auth, prefix []byte) ([]byte, cipher.Stream, error) {
	header := make([]byte, 161+len(auth))
	copy(header, prefix)
	if _, err := rand.Read(header[len(prefix):128]); err != nil {
		return nil, nil, err
	}
	copy(header[128:144], c.token[:])
	copy(header[144:], auth)
	offset := 144 + len(auth)
	header[offset] = 16
	iv := header[offset+1:]
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	return header, cipher.NewCTR(c.block, iv), nil
}

// Read exact fields; do not search for IV markers in opaque server material.
// A failed/truncated header must not publish a partial cache update.
func (c *Client) downlink(r io.Reader) (cipher.Stream, []byte, error) {
	fixed := make([]byte, 145)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return nil, nil, err
	}
	if subtle.ConstantTimeCompare(fixed[128:144], c.token[:]) != 1 {
		return nil, nil, errors.New("blackstone: token mismatch")
	}
	auth := make([]byte, 1+int(fixed[144]))
	auth[0] = fixed[144]
	if _, err := io.ReadFull(r, auth[1:]); err != nil {
		return nil, nil, err
	}
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, nil, err
	}
	if n[0] != 16 {
		return nil, nil, errors.New("blackstone: invalid IV length")
	}
	var iv [16]byte
	if _, err := io.ReadFull(r, iv[:]); err != nil {
		return nil, nil, err
	}
	return cipher.NewCTR(c.block, iv[:]), auth, nil
}

type Conn struct {
	net.Conn
	client            *Client
	auth, destination []byte
	readMu, writeMu   sync.Mutex
	reader, writer    cipher.Stream
	readErr, writeErr error
}

func (c *Client) StreamConn(conn net.Conn, destination []byte) *Conn {
	return &Conn{Conn: conn, client: c, auth: c.snapshot(), destination: append([]byte(nil), destination...)}
}
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.writer == nil {
		header, writer, err := c.client.uplink(c.auth, c.client.tcpFake)
		if err != nil {
			c.writeErr = err
			return 0, err
		}
		encrypted := make([]byte, len(c.destination))
		writer.XORKeyStream(encrypted, c.destination)
		header = append(header, encrypted...)
		if err = c.writeFrame(header); err != nil {
			return 0, err
		}
		c.writer = writer
	}
	if len(p) == 0 {
		return 0, nil
	}
	encrypted := make([]byte, len(p))
	c.writer.XORKeyStream(encrypted, p)
	if err := c.writeFrame(encrypted); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *Conn) writeFrame(p []byte) error {
	n, err := c.Conn.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.writeErr = err
		_ = c.Conn.Close()
	}
	return err
}
func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.reader == nil {
		stream, auth, err := c.client.downlink(c.Conn)
		if err != nil {
			c.readErr = err
			return 0, err
		}
		c.reader = stream
		c.client.publish(auth)
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.reader.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}
