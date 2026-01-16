//go:build !openssl_fips

// This file provides FIPS support using Go 1.24+'s native FIPS 140-3 module.
// When built without the openssl_fips tag, this implementation is used.

package fips

import (
	"fmt"
	"log"
	"os"
	"sync"
)

var (
	initialized   bool
	initializedMu sync.Mutex
	fipsEnabled   bool
)

// checkNativeFIPS checks if the native Go FIPS module is enabled.
// In Go 1.24+, this is controlled by GODEBUG=fips140=on
func checkNativeFIPS() bool {
	// Check GODEBUG environment variable
	godebug := os.Getenv("GODEBUG")
	if godebug == "" {
		return false
	}

	// Look for fips140=on in GODEBUG
	// GODEBUG format is comma-separated key=value pairs
	for _, part := range splitGODEBUG(godebug) {
		if part == "fips140=on" || part == "fips140=only" {
			return true
		}
	}
	return false
}

// splitGODEBUG splits the GODEBUG string into individual settings.
func splitGODEBUG(s string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if start < i {
				parts = append(parts, s[start:i])
			}
			start = i + 1
		}
	}
	return parts
}

// Enabled returns true if FIPS 140-3 mode is currently active.
func Enabled() bool {
	initializedMu.Lock()
	defer initializedMu.Unlock()

	if !initialized {
		fipsEnabled = checkNativeFIPS()
		initialized = true
	}
	return fipsEnabled
}

// GetStatus returns the current FIPS status.
func GetStatus() Status {
	return Status{
		Enabled:       Enabled(),
		Mode:          ModeNative,
		ModuleVersion: "Go Cryptographic Module v1.0.0",
		Certificate:   "A6650 (Review Pending)",
	}
}

// RequireFIPS ensures FIPS mode is enabled.
// Returns an error if FIPS is required but not available.
func RequireFIPS(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}

	if !Enabled() {
		if cfg.Strict {
			return fmt.Errorf("%w: set GODEBUG=fips140=on environment variable", ErrFIPSNotEnabled)
		}
		log.Printf("WARNING: FIPS mode requested but not enabled (non-strict mode)")
	}
	return nil
}

// Initialize sets up the FIPS module based on configuration.
// For native Go FIPS, this verifies the module is properly enabled.
func Initialize(cfg Config) error {
	if err := RequireFIPS(cfg); err != nil {
		return err
	}

	if cfg.Enabled {
		if Enabled() {
			log.Printf("FIPS 140-3 mode: enabled (native Go module)")
			log.Printf("FIPS module: Go Cryptographic Module v1.0.0")
			log.Printf("FIPS certificate: A6650 (Review Pending)")
		} else {
			log.Printf("FIPS 140-3 mode: requested but not active")
			log.Printf("To enable: set GODEBUG=fips140=on")
		}
	}

	return nil
}

// MustInitialize is like Initialize but panics on error.
// Use this in main() when FIPS compliance is mandatory.
func MustInitialize(cfg Config) {
	if err := Initialize(cfg); err != nil {
		panic(fmt.Sprintf("FIPS initialization failed: %v", err))
	}
}
