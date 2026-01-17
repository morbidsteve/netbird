//go:build fips

package openssl

import "time"

// DTLSConfig contains configuration for DTLS connections.
type DTLSConfig struct {
	// PSK is the pre-shared key for authentication
	PSK []byte

	// PSKIdentity is sent to the peer during handshake
	PSKIdentity []byte

	// IsServer indicates if this is the server side of the connection
	IsServer bool

	// MTU is the maximum transmission unit (0 for default)
	MTU int

	// HandshakeTimeout for handshake operations
	HandshakeTimeout time.Duration
}

// DefaultDTLSConfig returns a configuration with sensible defaults.
func DefaultDTLSConfig() *DTLSConfig {
	return &DTLSConfig{
		MTU:              1200,
		HandshakeTimeout: 30 * time.Second,
	}
}

// Validate checks the configuration for errors.
func (c *DTLSConfig) Validate() error {
	if len(c.PSK) == 0 {
		return ErrNoPSK
	}
	if len(c.PSK) < 16 {
		return ErrPSKTooShort
	}
	return nil
}
