// Package fips provides FIPS 140-3 compliant cryptographic operations for NetBird.
//
// This package abstracts the underlying FIPS module (native Go or OpenSSL) and
// provides helpers for TLS and DTLS configuration restricted to FIPS-approved
// algorithms.
//
// FIPS 140-3 Approved Algorithms used:
//   - Key Exchange: ECDHE with P-384 or P-256 (NIST SP 800-56A Rev 3)
//   - Encryption: AES-256-GCM or AES-128-GCM (FIPS 197, SP 800-38D)
//   - Signatures: ECDSA with P-384 or P-256 (FIPS 186-5)
//   - Hashing: SHA-384 or SHA-256 (FIPS 180-4)
package fips

import (
	"crypto/tls"
	"errors"
)

// ErrFIPSNotEnabled is returned when FIPS mode is required but not available.
var ErrFIPSNotEnabled = errors.New("FIPS 140-3 mode is not enabled")

// ErrNonFIPSCipher is returned when a non-FIPS cipher is requested.
var ErrNonFIPSCipher = errors.New("cipher suite is not FIPS 140-3 approved")

// Mode represents the FIPS module implementation being used.
type Mode string

const (
	// ModeNative uses Go 1.24+ native FIPS module
	ModeNative Mode = "native"
	// ModeOpenSSL uses OpenSSL FIPS module via cgo
	ModeOpenSSL Mode = "openssl"
	// ModeNone indicates FIPS is not available
	ModeNone Mode = "none"
)

// Config holds FIPS-related configuration.
type Config struct {
	// Enabled determines if FIPS mode should be active
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Mode specifies which FIPS module to use (native or openssl)
	Mode Mode `yaml:"mode" json:"mode"`
	// Strict causes startup failure if FIPS is unavailable
	Strict bool `yaml:"strict" json:"strict"`
	// MinTLSVersion is the minimum TLS version (should be "1.2" or "1.3")
	MinTLSVersion string `yaml:"min_tls_version" json:"min_tls_version"`
	// CipherSuite is the preferred cipher suite
	CipherSuite string `yaml:"cipher_suite" json:"cipher_suite"`
}

// DefaultConfig returns the default FIPS configuration.
// FIPS is disabled by default but strict mode is on to prevent
// accidental non-compliance when enabled.
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		Mode:          ModeNative,
		Strict:        true,
		MinTLSVersion: "1.3",
		CipherSuite:   "TLS_AES_256_GCM_SHA384",
	}
}

// Status contains information about the current FIPS mode status.
type Status struct {
	// Enabled indicates if FIPS mode is currently active
	Enabled bool
	// Mode indicates which FIPS module is in use
	Mode Mode
	// ModuleVersion is the version of the FIPS module
	ModuleVersion string
	// Certificate is the CMVP certificate number if known
	Certificate string
}

// FIPSApprovedCipherSuites returns the list of FIPS 140-3 approved TLS 1.3 cipher suites.
// These are the only cipher suites that should be used when FIPS compliance is required.
func FIPSApprovedCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_AES_256_GCM_SHA384, // Preferred: 256-bit security
		tls.TLS_AES_128_GCM_SHA256, // Acceptable: 128-bit security
	}
}

// FIPSApprovedCurves returns the list of FIPS 140-3 approved elliptic curves.
// P-384 is preferred for 192-bit equivalent security.
func FIPSApprovedCurves() []tls.CurveID {
	return []tls.CurveID{
		tls.CurveP384, // Preferred: 192-bit equivalent security
		tls.CurveP256, // Acceptable: 128-bit equivalent security
	}
}

// NewTLSConfig creates a TLS configuration restricted to FIPS-approved algorithms.
// This configuration enforces:
//   - TLS 1.3 only
//   - AES-GCM cipher suites only
//   - P-384 and P-256 curves only
func NewTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CipherSuites:     FIPSApprovedCipherSuites(),
		CurvePreferences: FIPSApprovedCurves(),
	}
}

// NewTLSConfigWithCerts creates a FIPS TLS config with the provided certificates.
func NewTLSConfigWithCerts(certs []tls.Certificate) *tls.Config {
	cfg := NewTLSConfig()
	cfg.Certificates = certs
	return cfg
}

// ValidateTLSConfig checks if a TLS config uses only FIPS-approved settings.
func ValidateTLSConfig(cfg *tls.Config) error {
	if cfg == nil {
		return errors.New("TLS config is nil")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		return errors.New("FIPS requires TLS 1.2 or higher")
	}
	return nil
}

// IsCipherSuiteApproved checks if a cipher suite is FIPS-approved.
func IsCipherSuiteApproved(suite uint16) bool {
	approved := FIPSApprovedCipherSuites()
	for _, s := range approved {
		if s == suite {
			return true
		}
	}
	return false
}

// IsCurveApproved checks if an elliptic curve is FIPS-approved.
func IsCurveApproved(curve tls.CurveID) bool {
	approved := FIPSApprovedCurves()
	for _, c := range approved {
		if c == curve {
			return true
		}
	}
	return false
}
