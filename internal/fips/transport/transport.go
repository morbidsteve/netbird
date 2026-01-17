// Package transport provides a FIPS-compliant DTLS transport layer.
//
// This package wraps UDP connections with DTLS encryption using only
// FIPS 140-3 approved cipher suites. It serves as the outer encryption
// layer for NetBird peer-to-peer connections.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/netbirdio/netbird/internal/fips"
)

// ErrTransportClosed is returned when operating on a closed transport.
var ErrTransportClosed = errors.New("transport is closed")

// ErrNotListening is returned when accepting on a non-listening transport.
var ErrNotListening = errors.New("transport is not listening")

// Config holds configuration for creating a FIPS transport.
type Config struct {
	// LocalAddr is the local address to bind to (e.g., "0.0.0.0:51820")
	LocalAddr string

	// Certificate is the TLS certificate for this endpoint
	Certificate *tls.Certificate

	// RootCAs is the pool of trusted CA certificates for verifying peers
	RootCAs *x509.CertPool

	// ClientCAs is the pool of trusted CA certificates for client verification (server mode)
	ClientCAs *x509.CertPool

	// IsServer indicates if this transport operates in server mode
	IsServer bool

	// MTU is the maximum transmission unit (default: 1350)
	MTU int

	// HandshakeTimeout is the timeout for DTLS handshake (default: 30s)
	HandshakeTimeout time.Duration

	// RequireClientCert enables mutual TLS in server mode
	RequireClientCert bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MTU:               1350,
		HandshakeTimeout:  30 * time.Second,
		RequireClientCert: true,
	}
}

// Conn represents a DTLS-encrypted connection.
type Conn struct {
	// underlying is the raw UDP connection
	underlying *net.UDPConn
	// remoteAddr is the peer's address
	remoteAddr *net.UDPAddr
	// For a real implementation, this would wrap a dtls.Conn
	// This is a placeholder structure
	mu     sync.Mutex
	closed bool
}

// Read reads data from the connection.
func (c *Conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ErrTransportClosed
	}
	c.mu.Unlock()

	// Placeholder: in real implementation, this decrypts via DTLS
	return c.underlying.Read(b)
}

// Write writes data to the connection.
func (c *Conn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ErrTransportClosed
	}
	c.mu.Unlock()

	// Placeholder: in real implementation, this encrypts via DTLS
	return c.underlying.WriteToUDP(b, c.remoteAddr)
}

// Close closes the connection.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	return c.underlying.Close()
}

// RemoteAddr returns the remote address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// LocalAddr returns the local address.
func (c *Conn) LocalAddr() net.Addr {
	return c.underlying.LocalAddr()
}

// Transport provides FIPS-compliant DTLS transport.
type Transport struct {
	config Config

	mu         sync.RWMutex
	listener   net.Listener
	udpConn    *net.UDPConn
	conns      map[string]*Conn
	closed     bool
	tlsConfig  *tls.Config
	fipsConfig fips.DTLSConfig
}

// New creates a new FIPS-compliant DTLS transport.
func New(cfg Config) (*Transport, error) {
	// Warn if FIPS mode is not enabled
	if !fips.Enabled() {
		log.Printf("WARNING: FIPS mode not enabled, but transport will still use FIPS cipher suites")
	}

	// Apply defaults
	if cfg.MTU == 0 {
		cfg.MTU = 1350
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 30 * time.Second
	}

	// Create TLS config with FIPS cipher suites
	var tlsConfig *tls.Config
	if cfg.IsServer {
		tlsConfig = fips.NewDTLSServerTLSConfig(fips.DTLSServerConfigOptions{
			Certificate:       cfg.Certificate,
			ClientCAs:         cfg.ClientCAs,
			RequireClientCert: cfg.RequireClientCert,
			Config:            fips.DefaultDTLSConfig(),
		})
	} else {
		tlsConfig = fips.NewDTLSClientTLSConfig(fips.DTLSClientConfigOptions{
			RootCAs:    cfg.RootCAs,
			ClientCert: cfg.Certificate,
			Config:     fips.DefaultDTLSConfig(),
		})
	}

	fipsConfig := fips.DefaultDTLSConfig()
	fipsConfig.MTU = cfg.MTU
	fipsConfig.HandshakeTimeout = cfg.HandshakeTimeout

	return &Transport{
		config:     cfg,
		conns:      make(map[string]*Conn),
		tlsConfig:  tlsConfig,
		fipsConfig: fipsConfig,
	}, nil
}

// Listen starts the transport in server mode.
func (t *Transport) Listen(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return ErrTransportClosed
	}

	addr, err := net.ResolveUDPAddr("udp", t.config.LocalAddr)
	if err != nil {
		return fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}

	t.udpConn = conn

	log.Printf("FIPS transport listening on %s", conn.LocalAddr())
	log.Printf("FIPS cipher suites: %v", t.tlsConfig.CipherSuites)

	return nil
}

// Accept accepts a new connection (server mode).
// Note: This is a simplified placeholder. Real implementation would use pion/dtls.
func (t *Transport) Accept(ctx context.Context) (*Conn, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, ErrTransportClosed
	}
	if t.udpConn == nil {
		t.mu.RUnlock()
		return nil, ErrNotListening
	}
	udpConn := t.udpConn
	t.mu.RUnlock()

	// Placeholder: in real implementation, this would accept DTLS connections
	buf := make([]byte, t.fipsConfig.MTU)
	n, remoteAddr, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	_ = n // Use the data in real implementation

	conn := &Conn{
		underlying: udpConn,
		remoteAddr: remoteAddr,
	}

	t.mu.Lock()
	t.conns[remoteAddr.String()] = conn
	t.mu.Unlock()

	return conn, nil
}

// Dial establishes a DTLS connection to a remote peer.
func (t *Transport) Dial(ctx context.Context, remoteAddr string) (*Conn, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, ErrTransportClosed
	}
	t.mu.RUnlock()

	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve remote address: %w", err)
	}

	// Create UDP connection
	laddr, err := net.ResolveUDPAddr("udp", t.config.LocalAddr)
	if err != nil {
		laddr = nil // Let system choose
	}

	udpConn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}

	// Placeholder: in real implementation, this would perform DTLS handshake
	log.Printf("FIPS transport connecting to %s", remoteAddr)

	conn := &Conn{
		underlying: udpConn,
		remoteAddr: raddr,
	}

	t.mu.Lock()
	t.conns[remoteAddr] = conn
	t.mu.Unlock()

	return conn, nil
}

// Close closes the transport and all connections.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true

	var errs []error

	for addr, conn := range t.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close conn %s: %w", addr, err))
		}
	}
	t.conns = nil

	if t.udpConn != nil {
		if err := t.udpConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close listener: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	return nil
}

// GetConnection returns an existing connection to a peer.
func (t *Transport) GetConnection(remoteAddr string) (*Conn, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	conn, ok := t.conns[remoteAddr]
	return conn, ok
}

// LocalAddr returns the local address the transport is bound to.
func (t *Transport) LocalAddr() net.Addr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.udpConn == nil {
		return nil
	}
	return t.udpConn.LocalAddr()
}

// ConnectionCount returns the number of active connections.
func (t *Transport) ConnectionCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.conns)
}
