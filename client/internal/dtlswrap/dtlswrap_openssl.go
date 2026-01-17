//go:build fips

// Package dtlswrap provides DTLS encryption wrapping for peer connections.
//
// This file uses OpenSSL FIPS provider (Certificate #4282) for FIPS 140-3
// validated encryption.
package dtlswrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/internal/fips"
	"github.com/netbirdio/netbird/internal/fips/openssl"
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

// Wrap wraps an existing net.Conn with DTLS encryption using OpenSSL FIPS.
// If DTLS is not enabled in config, returns the original connection.
func Wrap(ctx context.Context, conn net.Conn, cfg Config) (net.Conn, error) {
	if !cfg.Enabled {
		return conn, nil
	}

	// Initialize OpenSSL FIPS if not already done
	if err := openssl.InitFIPS(); err != nil {
		if cfg.FIPSRequired {
			return nil, fmt.Errorf("%w: OpenSSL FIPS init failed: %v", ErrFIPSRequired, err)
		}
		// Fall through without FIPS if not required
		log.WithError(err).Warn("OpenSSL FIPS initialization failed, continuing without FIPS")
	}

	// Check FIPS mode if required
	if cfg.FIPSRequired && !openssl.IsFIPSEnabled() {
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
		"peer":    peerKeyShort,
		"role":    roleString(cfg.IsInitiator),
		"fips":    openssl.IsFIPSEnabled(),
		"backend": "openssl",
	})

	logger.Debug("Wrapping connection with OpenSSL DTLS (FIPS)")

	// Derive PSK from public keys
	psk := derivePSK(cfg.LocalPublicKey, cfg.PeerPublicKey)

	// Configure OpenSSL DTLS
	dtlsConfig := &openssl.DTLSConfig{
		PSK:              psk,
		PSKIdentity:      []byte(cfg.LocalPublicKey),
		IsServer:         !cfg.IsInitiator,
		MTU:              cfg.MTU,
		HandshakeTimeout: cfg.HandshakeTimeout,
	}

	dtlsConn, err := openssl.NewDTLSConn(conn, dtlsConfig)
	if err != nil {
		logger.WithError(err).Error("Failed to create OpenSSL DTLS connection")
		return nil, fmt.Errorf("create DTLS connection: %w", err)
	}

	// Create handshake context with timeout
	handshakeCtx, cancel := context.WithTimeout(ctx, cfg.HandshakeTimeout)
	defer cancel()

	if err := dtlsConn.Handshake(handshakeCtx); err != nil {
		dtlsConn.Close()
		logger.WithError(err).Error("OpenSSL DTLS handshake failed")
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	logger.WithField("cipher", dtlsConn.CipherSuite()).Info("OpenSSL DTLS connection established (FIPS)")
	return dtlsConn, nil
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

// roleString returns a string representation of the handshake role.
func roleString(isInitiator bool) string {
	if isInitiator {
		return "client"
	}
	return "server"
}

// IsEnabled returns whether DTLS wrapping is enabled.
// In FIPS build, checks OpenSSL FIPS status.
func IsEnabled() bool {
	return fips.Enabled() || openssl.IsFIPSEnabled()
}

// GetConfig returns a DTLS config based on FIPS settings.
func GetConfig(peerKey, localKey string, isInitiator bool) Config {
	cfg := DefaultConfig()
	cfg.Enabled = IsEnabled()
	cfg.FIPSRequired = openssl.IsFIPSEnabled()
	cfg.PeerPublicKey = peerKey
	cfg.LocalPublicKey = localKey
	cfg.IsInitiator = isInitiator
	return cfg
}
