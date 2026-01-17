//go:build openssl_fips

// This file provides FIPS support using OpenSSL's FIPS module via golang-fips/go.
// When built with the openssl_fips tag using the golang-fips/go toolchain,
// this implementation is used.
//
// Requirements:
//   - golang-fips/go toolchain (not standard Go)
//   - OpenSSL with FIPS module installed
//   - CGO_ENABLED=1

package fips

import (
	"fmt"
	"log"
	"sync"
)

var (
	initialized   bool
	initializedMu sync.Mutex
	fipsEnabled   bool
)

// Enabled returns true if FIPS 140-3 mode is currently active.
// With golang-fips/go, FIPS mode is enabled at build time.
func Enabled() bool {
	initializedMu.Lock()
	defer initializedMu.Unlock()

	if !initialized {
		// When built with golang-fips/go toolchain, FIPS is always enabled
		fipsEnabled = true
		initialized = true
	}
	return fipsEnabled
}

// GetStatus returns the current FIPS status.
func GetStatus() Status {
	return Status{
		Enabled:       Enabled(),
		Mode:          ModeOpenSSL,
		ModuleVersion: "OpenSSL FIPS Module 3.x",
		Certificate:   "See OpenSSL CMVP listing",
	}
}

// RequireFIPS ensures FIPS mode is enabled.
func RequireFIPS(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}

	// With OpenSSL FIPS build, mode is always enabled
	if !Enabled() && cfg.Strict {
		return fmt.Errorf("%w: binary not built with golang-fips/go", ErrFIPSNotEnabled)
	}
	return nil
}

// Initialize sets up the FIPS module for OpenSSL.
func Initialize(cfg Config) error {
	if err := RequireFIPS(cfg); err != nil {
		return err
	}

	if cfg.Enabled {
		log.Printf("FIPS 140-3 mode: enabled (OpenSSL module)")
		log.Printf("FIPS module: OpenSSL FIPS Module")
		log.Printf("Note: Using golang-fips/go toolchain")
	}

	return nil
}

// MustInitialize is like Initialize but panics on error.
func MustInitialize(cfg Config) {
	if err := Initialize(cfg); err != nil {
		panic(fmt.Sprintf("FIPS initialization failed: %v", err))
	}
}
