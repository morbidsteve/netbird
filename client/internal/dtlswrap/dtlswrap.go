// Package dtlswrap provides DTLS encryption wrapping for peer connections.
//
// This package wraps raw UDP connections (from ICE) with DTLS encryption
// using FIPS 140-3 approved cipher suites. It implements the net.Conn interface
// so it can be used transparently by the WireGuard proxy.
package dtlswrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/internal/fips"
)

var (
	// ErrFIPSRequired is returned when FIPS mode is required but not available.
	ErrFIPSRequired = errors.New("FIPS mode required but not enabled")
	// ErrHandshakeFailed is returned when DTLS handshake fails.
	ErrHandshakeFailed = errors.New("DTLS handshake failed")
	// ErrClosed is returned when operating on a closed connection.
	ErrClosed = errors.New("connection closed")
	// ErrInvalidKey is returned when peer public key is invalid.
	ErrInvalidKey = errors.New("invalid peer public key")
)

// Config holds configuration for DTLS wrapping.
type Config struct {
	// Enabled determines if DTLS wrapping is active
	Enabled bool
	// FIPSRequired fails if FIPS mode is not available
	FIPSRequired bool
	// HandshakeTimeout is the maximum time for DTLS handshake
	HandshakeTimeout time.Duration
	// MTU is the maximum transmission unit
	MTU int
	// IsInitiator determines handshake role (true = client, false = server)
	IsInitiator bool
	// PeerPublicKey is the remote peer's WireGuard public key (base64)
	PeerPublicKey string
	// LocalPublicKey is the local WireGuard public key (base64)
	LocalPublicKey string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:          false,
		FIPSRequired:     false,
		HandshakeTimeout: 30 * time.Second,
		MTU:              1350,
	}
}

// Conn wraps a net.Conn with DTLS encryption using pion/dtls.
type Conn struct {
	dtlsConn   *dtls.Conn
	underlying net.Conn
	config     Config
	log        *log.Entry

	mu     sync.Mutex
	closed bool
}

// connAdapter wraps net.Conn to implement net.PacketConn for pion/dtls.
type connAdapter struct {
	conn       net.Conn
	remoteAddr net.Addr
}

func (c *connAdapter) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(b)
	return n, c.remoteAddr, err
}

func (c *connAdapter) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.conn.Write(b)
}

func (c *connAdapter) Close() error {
	return c.conn.Close()
}

func (c *connAdapter) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *connAdapter) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *connAdapter) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connAdapter) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Wrap wraps an existing net.Conn with DTLS encryption.
// If DTLS is not enabled in config, returns the original connection.
func Wrap(ctx context.Context, conn net.Conn, cfg Config) (net.Conn, error) {
	if !cfg.Enabled {
		return conn, nil
	}

	// Check FIPS mode if required
	if cfg.FIPSRequired && !fips.Enabled() {
		return nil, ErrFIPSRequired
	}

	if cfg.PeerPublicKey == "" {
		return nil, ErrInvalidKey
	}

	peerKeyShort := cfg.PeerPublicKey
	if len(peerKeyShort) > 8 {
		peerKeyShort = peerKeyShort[:8] + "..."
	}

	logger := log.WithFields(log.Fields{
		"peer": peerKeyShort,
		"role": roleString(cfg.IsInitiator),
		"fips": fips.Enabled(),
	})

	logger.Debug("Wrapping connection with DTLS")

	wrapped := &Conn{
		underlying: conn,
		config:     cfg,
		log:        logger,
	}

	// Perform DTLS handshake
	if err := wrapped.handshake(ctx); err != nil {
		logger.WithError(err).Error("DTLS handshake failed")
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	logger.Info("DTLS connection established")
	return wrapped, nil
}

// derivePSK derives a PSK from local and peer public keys.
// Uses SHA-256 to create a deterministic 32-byte key.
func derivePSK(localKey, peerKey string) []byte {
	// Combine keys in sorted order for determinism
	var combined string
	if localKey < peerKey {
		combined = localKey + peerKey
	} else {
		combined = peerKey + localKey
	}

	// Add a domain separator for security
	combined = "netbird-dtls-psk-v1:" + combined

	hash := sha256.Sum256([]byte(combined))
	return hash[:]
}

// handshake performs the DTLS handshake using pion/dtls with PSK.
func (c *Conn) handshake(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dtlsConn != nil {
		return nil
	}

	// Create handshake context with timeout
	handshakeCtx, cancel := context.WithTimeout(ctx, c.config.HandshakeTimeout)
	defer cancel()

	// Derive PSK from public keys
	psk := derivePSK(c.config.LocalPublicKey, c.config.PeerPublicKey)

	// Configure DTLS with FIPS-approved settings
	// Using PSK with AES-128-GCM (FIPS 197 + SP 800-38D approved)
	dtlsConfig := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			return psk, nil
		},
		PSKIdentityHint: []byte(c.config.LocalPublicKey),
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		},
		MTU:                  c.config.MTU,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		FlightInterval:       100 * time.Millisecond,
	}

	c.log.WithField("ciphers", fmt.Sprintf("%v", dtlsConfig.CipherSuites)).Debug("Using FIPS cipher suites")

	// Adapt net.Conn to net.PacketConn for pion/dtls
	adapter := &connAdapter{
		conn:       c.underlying,
		remoteAddr: c.underlying.RemoteAddr(),
	}

	// Set deadline on underlying connection for handshake timeout
	if deadline, ok := handshakeCtx.Deadline(); ok {
		if err := c.underlying.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set handshake deadline: %w", err)
		}
		defer c.underlying.SetDeadline(time.Time{}) // Clear deadline after handshake
	}

	var dtlsConn *dtls.Conn
	var err error

	if c.config.IsInitiator {
		// Client role
		dtlsConn, err = dtls.Client(adapter, c.underlying.RemoteAddr(), dtlsConfig)
	} else {
		// Server role
		dtlsConn, err = dtls.Server(adapter, c.underlying.RemoteAddr(), dtlsConfig)
	}

	if err != nil {
		return fmt.Errorf("DTLS handshake: %w", err)
	}

	c.dtlsConn = dtlsConn
	return nil
}

// Read reads data from the DTLS connection.
func (c *Conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ErrClosed
	}
	dtlsConn := c.dtlsConn
	c.mu.Unlock()

	if dtlsConn == nil {
		return 0, ErrClosed
	}

	return dtlsConn.Read(b)
}

// Write writes data to the DTLS connection.
func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ErrClosed
	}
	dtlsConn := c.dtlsConn
	c.mu.Unlock()

	if dtlsConn == nil {
		return 0, ErrClosed
	}

	return dtlsConn.Write(b)
}

// Close closes the DTLS connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	c.log.Debug("Closing DTLS connection")

	var errs []error

	if c.dtlsConn != nil {
		if err := c.dtlsConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Don't close underlying - it's managed by the caller
	// Just close the DTLS layer

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	return nil
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.underlying.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.underlying.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	dtlsConn := c.dtlsConn
	c.mu.Unlock()

	if dtlsConn != nil {
		return dtlsConn.SetDeadline(t)
	}
	return c.underlying.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	dtlsConn := c.dtlsConn
	c.mu.Unlock()

	if dtlsConn != nil {
		return dtlsConn.SetReadDeadline(t)
	}
	return c.underlying.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	dtlsConn := c.dtlsConn
	c.mu.Unlock()

	if dtlsConn != nil {
		return dtlsConn.SetWriteDeadline(t)
	}
	return c.underlying.SetWriteDeadline(t)
}

// ConnectionState returns the DTLS connection state if available.
func (c *Conn) ConnectionState() (dtls.State, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dtlsConn == nil {
		return dtls.State{}, false
	}

	return c.dtlsConn.ConnectionState()
}

// roleString returns a string representation of the handshake role.
func roleString(isInitiator bool) string {
	if isInitiator {
		return "client"
	}
	return "server"
}

// IsEnabled returns whether DTLS wrapping is enabled.
func IsEnabled() bool {
	return fips.Enabled()
}

// GetConfig returns a DTLS config based on FIPS settings.
func GetConfig(peerKey, localKey string, isInitiator bool) Config {
	cfg := DefaultConfig()
	cfg.Enabled = IsEnabled()
	cfg.FIPSRequired = fips.Enabled()
	cfg.PeerPublicKey = peerKey
	cfg.LocalPublicKey = localKey
	cfg.IsInitiator = isInitiator
	return cfg
}
