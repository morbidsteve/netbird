// Server-side FIPS helpers for management, signal, and relay servers.

package fips

import (
	"crypto/tls"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

// ServerConfig holds FIPS configuration for server components.
type ServerConfig struct {
	// FIPSEnabled determines if FIPS mode should be enforced
	FIPSEnabled bool
	// Strict causes startup failure if FIPS is unavailable
	Strict bool
}

// GetServerConfig returns FIPS server configuration from environment.
func GetServerConfig() ServerConfig {
	return ServerConfig{
		FIPSEnabled: os.Getenv("NETBIRD_FIPS_ENABLED") == "true",
		Strict:      os.Getenv("NETBIRD_FIPS_STRICT") != "false", // strict by default
	}
}

// InitServer initializes FIPS mode for server components.
// Call this early in server startup (management, signal, relay).
func InitServer() error {
	cfg := GetServerConfig()

	if !cfg.FIPSEnabled {
		return nil
	}

	fipsCfg := Config{
		Enabled: cfg.FIPSEnabled,
		Mode:    ModeNative,
		Strict:  cfg.Strict,
	}

	if err := Initialize(fipsCfg); err != nil {
		return fmt.Errorf("FIPS server initialization failed: %w", err)
	}

	status := GetStatus()
	if status.Enabled {
		log.Infof("Server FIPS 140-3 mode: enabled (%s, %s)", status.Mode, status.ModuleVersion)
	}

	return nil
}

// MustInitServer is like InitServer but logs fatal on error.
func MustInitServer() {
	if err := InitServer(); err != nil {
		log.Fatalf("FIPS server initialization failed: %v", err)
	}
}

// ApplyToTLSConfig modifies a TLS config to use only FIPS-approved settings.
// If FIPS mode is not enabled, returns the original config unchanged.
// If cfg is nil and FIPS is enabled, returns a new FIPS-compliant config.
func ApplyToTLSConfig(cfg *tls.Config) *tls.Config {
	if !Enabled() {
		if cfg == nil {
			return &tls.Config{}
		}
		return cfg
	}

	if cfg == nil {
		return NewTLSConfig()
	}

	// Clone and modify for FIPS compliance
	fipsCfg := cfg.Clone()
	fipsCfg.MinVersion = tls.VersionTLS12
	fipsCfg.MaxVersion = tls.VersionTLS13

	// Restrict to FIPS-approved cipher suites
	// For TLS 1.3, cipher suites are fixed by the protocol, but we set them anyway
	// For TLS 1.2, this restricts to AES-GCM with ECDHE
	fipsCfg.CipherSuites = []uint16{
		// TLS 1.3 (automatically used)
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_AES_128_GCM_SHA256,
		// TLS 1.2 fallback
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	// Restrict to FIPS-approved curves
	fipsCfg.CurvePreferences = FIPSApprovedCurves()

	log.Debug("Applied FIPS 140-3 settings to TLS configuration")
	return fipsCfg
}

// NewServerTLSConfig creates a new TLS config for servers with FIPS settings applied.
func NewServerTLSConfig(certs []tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		Certificates: certs,
	}
	return ApplyToTLSConfig(cfg)
}

// WrapGRPCTLSConfig wraps a gRPC TLS config with FIPS settings.
// This is specifically for gRPC servers (management, signal).
func WrapGRPCTLSConfig(cfg *tls.Config) *tls.Config {
	fipsCfg := ApplyToTLSConfig(cfg)

	// gRPC-specific settings
	fipsCfg.NextProtos = []string{"h2"} // HTTP/2 for gRPC

	return fipsCfg
}

// LogFIPSStatus logs the current FIPS status at server startup.
func LogFIPSStatus() {
	status := GetStatus()

	if status.Enabled {
		log.WithFields(log.Fields{
			"mode":    status.Mode,
			"module":  status.ModuleVersion,
			"cert":    status.Certificate,
		}).Info("FIPS 140-3 mode active")
	} else {
		log.Debug("FIPS 140-3 mode not enabled")
	}
}
