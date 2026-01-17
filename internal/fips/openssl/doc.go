// Package openssl provides cgo bindings to OpenSSL 3.0 with FIPS provider support.
//
// This package implements DTLS connections using OpenSSL's FIPS-validated
// cryptographic module (Certificate #4282) for federal compliance requirements.
//
// Build with: CGO_ENABLED=1 go build -tags fips
package openssl
