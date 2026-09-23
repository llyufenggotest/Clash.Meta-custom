package tls

import (
	"net"

	utls "github.com/metacubex/utls"
)

func DisableRenegotiationForECH(c *UConn) error {
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	for _, extension := range c.Extensions {
		if renegotiation, ok := extension.(*utls.RenegotiationInfoExtension); ok {
			renegotiation.Renegotiation = utls.RenegotiateNever
		}
	}
	return nil
}

func NewECHUClient(c net.Conn, config *Config, fingerprint UClientHelloID) (*UConn, error) {
	conn := UClient(c, config, fingerprint)
	if len(config.EncryptedClientHelloConfigList) > 0 {
		if err := DisableRenegotiationForECH(conn); err != nil {
			return nil, err
		}
	}
	return conn, nil
}
