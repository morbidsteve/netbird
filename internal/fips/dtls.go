// DTLS configuration for FIPS-compliant peer-to-peer connections.
//
// This file provides helpers for creating DTLS 1.2/1.3 configurations
// that use only FIPS-approved cipher suites. DTLS is used as the outer
// encryption layer around WireGuard tunnels.

package fips

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// DTLSConfig holds FIPS-compliant DTLS configuration options.
type DTLSConfig struct {
	// MTU is the maximum transmission unit for DTLS packets.
	// Should account for DTLS overhead (~45 bytes) plus WireGuard overhead (~60 bytes).
	// Default: 1350 (safe for most networks)
	MTU int `yaml:"mtu" json:"mtu"`

	// SessionTimeout is how long DTLS sessions remain valid.
	// Default: 1 hour
	SessionTimeout time.Duration `yaml:"session_timeout" json:"session_timeout"`

	// HandshakeTimeout is the maximum time for DTLS handshake.
	// Default: 30 seconds
	HandshakeTimeout time.Duration `yaml:"handshake_timeout" json:"handshake_timeout"`

	// InsecureSkipVerify disables certificate verification (NEVER use in production).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

// DefaultDTLSConfig returns sensible defaults for FIPS DTLS.
func DefaultDTLSConfig() DTLSConfig {
	return DTLSConfig{
		MTU:              1350,
		SessionTimeout:   time.Hour,
		HandshakeTimeout: 30 * time.Second,
	}
}

// DTLSCipherSuite represents a DTLS cipher suite identifier.
// Note: These are TLS 1.2 cipher suite values used by DTLS.
type DTLSCipherSuite uint16

// FIPS-approved DTLS cipher suites (TLS 1.2 format).
// These use ECDHE for key exchange and AES-GCM for encryption.
const (
	// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 - Preferred for FIPS
	DTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 DTLSCipherSuite = 0xc02c
	// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	DTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 DTLSCipherSuite = 0xc030
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	DTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 DTLSCipherSuite = 0xc02b
	// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	DTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 DTLSCipherSuite = 0xc02f
)

// FIPSApprovedDTLSCipherSuites returns the list of FIPS-approved DTLS cipher suites.
// These are ordered by preference (strongest first).
func FIPSApprovedDTLSCipherSuites() []DTLSCipherSuite {
	return []DTLSCipherSuite{
		DTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		DTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		DTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		DTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}

// FIPSApprovedDTLSCipherSuitesUint16 returns cipher suites as uint16 for compatibility.
func FIPSApprovedDTLSCipherSuitesUint16() []uint16 {
	suites := FIPSApprovedDTLSCipherSuites()
	result := make([]uint16, len(suites))
	for i, s := range suites {
		result[i] = uint16(s)
	}
	return result
}

// IsDTLSCipherSuiteApproved checks if a DTLS cipher suite is FIPS-approved.
func IsDTLSCipherSuiteApproved(suite DTLSCipherSuite) bool {
	approved := FIPSApprovedDTLSCipherSuites()
	for _, s := range approved {
		if s == suite {
			return true
		}
	}
	return false
}

// DTLSClientConfig creates configuration for a DTLS client.
// The returned tls.Config can be adapted for use with pion/dtls or other DTLS libraries.
type DTLSClientConfigOptions struct {
	// ServerName is the expected server name for verification
	ServerName string
	// RootCAs is the pool of trusted CA certificates
	RootCAs *x509.CertPool
	// ClientCert is the optional client certificate for mutual TLS
	ClientCert *tls.Certificate
	// Config is the DTLS-specific configuration
	Config DTLSConfig
}

// NewDTLSClientTLSConfig creates a tls.Config suitable for DTLS client connections.
// Note: This creates a tls.Config that can be adapted for DTLS libraries.
func NewDTLSClientTLSConfig(opts DTLSClientConfigOptions) *tls.Config {
	cfg := &tls.Config{
		ServerName:         opts.ServerName,
		RootCAs:            opts.RootCAs,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12, // DTLS 1.2 maps to TLS 1.2
		CipherSuites:       FIPSApprovedDTLSCipherSuitesUint16(),
		CurvePreferences:   FIPSApprovedCurves(),
		InsecureSkipVerify: opts.Config.InsecureSkipVerify,
	}

	if opts.ClientCert != nil {
		cfg.Certificates = []tls.Certificate{*opts.ClientCert}
	}

	return cfg
}

// DTLSServerConfigOptions holds options for creating DTLS server config.
type DTLSServerConfigOptions struct {
	// Certificate is the server's certificate
	Certificate *tls.Certificate
	// ClientCAs is the pool of trusted client CA certificates (for mutual TLS)
	ClientCAs *x509.CertPool
	// RequireClientCert enables mutual TLS
	RequireClientCert bool
	// Config is the DTLS-specific configuration
	Config DTLSConfig
}

// NewDTLSServerTLSConfig creates a tls.Config suitable for DTLS server connections.
func NewDTLSServerTLSConfig(opts DTLSServerConfigOptions) *tls.Config {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS12,
		CipherSuites:     FIPSApprovedDTLSCipherSuitesUint16(),
		CurvePreferences: FIPSApprovedCurves(),
		ClientCAs:        opts.ClientCAs,
	}

	if opts.Certificate != nil {
		cfg.Certificates = []tls.Certificate{*opts.Certificate}
	}

	if opts.RequireClientCert {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg
}

// ValidateDTLSConfig validates DTLS configuration values.
func ValidateDTLSConfig(cfg DTLSConfig) error {
	if cfg.MTU < 576 {
		return ErrInvalidMTU
	}
	if cfg.MTU > 1500 {
		return ErrInvalidMTU
	}
	if cfg.SessionTimeout < time.Minute {
		return ErrInvalidTimeout
	}
	if cfg.HandshakeTimeout < time.Second {
		return ErrInvalidTimeout
	}
	return nil
}

// ErrInvalidMTU indicates an invalid MTU value.
var ErrInvalidMTU = errorf("MTU must be between 576 and 1500")

// ErrInvalidTimeout indicates an invalid timeout value.
var ErrInvalidTimeout = errorf("timeout value is invalid")

// errorf creates a simple error.
func errorf(msg string) error {
	return &configError{msg: msg}
}

type configError struct {
	msg string
}

func (e *configError) Error() string {
	return e.msg
}
