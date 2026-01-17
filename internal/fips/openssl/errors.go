//go:build fips

package openssl

import "errors"

var (
	// ErrNoPSK is returned when no PSK is provided
	ErrNoPSK = errors.New("openssl: PSK is required")

	// ErrPSKTooShort is returned when PSK is less than 16 bytes
	ErrPSKTooShort = errors.New("openssl: PSK must be at least 16 bytes")

	// ErrHandshakeFailed is returned when DTLS handshake fails
	ErrHandshakeFailed = errors.New("openssl: DTLS handshake failed")

	// ErrNotInitialized is returned when FIPS is not initialized
	ErrNotInitialized = errors.New("openssl: FIPS provider not initialized")

	// ErrConnectionClosed is returned when operating on closed connection
	ErrConnectionClosed = errors.New("openssl: connection closed")
)
