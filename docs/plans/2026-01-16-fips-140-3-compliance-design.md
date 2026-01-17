# FIPS 140-3 Compliance Design for NetBird

**Date**: 2026-01-16
**Status**: Approved
**Author**: Architecture Team

## Executive Summary

This document describes the design for making NetBird FIPS 140-3 compliant to enable transmission of Controlled Unclassified Information (CUI) over untrusted networks. The approach adds a DTLS 1.3 encryption wrapper with FIPS-approved algorithms around existing WireGuard tunnels, while updating all other components to use FIPS-validated cryptographic modules.

## Table of Contents

1. [Requirements](#requirements)
2. [Architecture Overview](#architecture-overview)
3. [DTLS 1.3 Wrapper Layer](#dtls-13-wrapper-layer)
4. [Component Changes](#component-changes)
5. [Go FIPS Module Integration](#go-fips-module-integration)
6. [Key Management](#key-management)
7. [Compliance Mapping](#compliance-mapping)
8. [Build and Deployment](#build-and-deployment)
9. [Testing Strategy](#testing-strategy)
10. [References](#references)

---

## Requirements

### Regulatory Context

- **FIPS 140-3**: Federal Information Processing Standard for cryptographic module validation
- **NIST SP 800-171 Rev 3**: Protecting Controlled Unclassified Information in Nonfederal Systems
- **CUI**: Controlled Unclassified Information requiring protection per federal contracts

### Key Constraints

1. Must use FIPS 140-3 validated cryptographic modules
2. Must support self-hosted deployment
3. Must work over untrusted networks (internet)
4. Must maintain existing NetBird functionality (mesh networking, NAT traversal, ACLs)
5. Performance overhead acceptable (not ultra-low-latency requirements)

### Timeline Considerations

- FIPS 140-2 validated modules accepted until **September 21, 2026**
- After this date, only FIPS 140-3 validated modules permitted
- Go 1.24+ native FIPS module currently in CMVP validation queue

---

## Architecture Overview

### Design Principle

Add a FIPS-compliant encryption layer (DTLS 1.3) around existing WireGuard tunnels. WireGuard handles mesh networking, peer discovery, and NAT traversal. DTLS 1.3 provides the FIPS-validated encryption that satisfies regulatory requirements.

### System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    FIPS-Compliant NetBird                       │
└─────────────────────────────────────────────────────────────────┘

  Peer A                                                    Peer B
┌──────────────────┐                                ┌──────────────────┐
│  Application     │                                │  Application     │
├──────────────────┤                                ├──────────────────┤
│  NetBird Client  │                                │  NetBird Client  │
├──────────────────┤                                ├──────────────────┤
│  WireGuard       │  ◄─── Inner tunnel ───►        │  WireGuard       │
│  (Curve25519 +   │       (preserved for           │  (Curve25519 +   │
│   ChaCha20)      │        mesh logic)             │   ChaCha20)      │
├──────────────────┤                                ├──────────────────┤
│  DTLS 1.3 FIPS   │  ◄─── Outer tunnel ───►        │  DTLS 1.3 FIPS   │
│  (P-384 + AES-   │       (FIPS-validated          │  (P-384 + AES-   │
│   256-GCM)       │        encryption)             │   256-GCM)       │
├──────────────────┤                                ├──────────────────┤
│  UDP Transport   │  ◄─── Untrusted Net ───►       │  UDP Transport   │
└──────────────────┘                                └──────────────────┘
```

### Preserved Functionality

- Mesh networking and peer discovery
- NAT traversal and hole punching
- Access control lists and policies
- DNS management and routes
- Multi-platform support
- Management UI and API
- SSO/identity provider integration

---

## DTLS 1.3 Wrapper Layer

### Protocol Selection

**DTLS 1.3** (RFC 9147) over UDP

Rationale:
- Preserves UDP semantics that WireGuard expects
- Standard protocol with FIPS cipher suites
- Better for VPN traffic than TCP-based TLS (no head-of-line blocking)
- Easier to explain to auditors

### FIPS-Approved Cipher Suite

```
TLS_AES_256_GCM_SHA384 with ECDHE P-384
```

| Component | Algorithm | FIPS Reference |
|-----------|-----------|----------------|
| Key Exchange | ECDHE P-384 | NIST SP 800-56A Rev 3 |
| Encryption | AES-256-GCM | FIPS 197, SP 800-38D |
| Hash/PRF | SHA-384 | FIPS 180-4 |
| Signatures | ECDSA P-384 | FIPS 186-5 |

### Packet Flow

```
Application Data
       │
       ▼
┌─────────────────┐
│ WireGuard       │  Encrypts with ChaCha20-Poly1305
│ Encapsulation   │  (inner layer - defense in depth)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ DTLS 1.3        │  Encrypts with AES-256-GCM
│ Record Layer    │  (outer layer - FIPS compliant)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ UDP Datagram    │  Sent over untrusted network
└─────────────────┘
```

### Handshake Sequence

1. DTLS 1.3 handshake establishes FIPS-encrypted channel
2. WireGuard handshake occurs inside protected tunnel
3. Application data flows through both encryption layers

### Session Management

- **Session Resumption**: DTLS session tickets (encrypted with AES-256-GCM) allow fast reconnection
- **Rekeying**: Automatic per DTLS 1.3 specification
- **Timeout**: Configurable idle timeout with keepalive support

### MTU Handling

| Layer | Overhead | Notes |
|-------|----------|-------|
| Ethernet MTU | 1500 bytes | Standard |
| DTLS overhead | ~45 bytes | Header + auth tag |
| WireGuard overhead | ~60 bytes | Header + auth tag |
| **Safe inner MTU** | **~1350 bytes** | Configurable |

---

## Component Changes

### Client (Daemon)

| File/Area | Current | Change |
|-----------|---------|--------|
| `client/iface/` | Direct WireGuard UDP | Wrap in DTLS 1.3 transport |
| `encryption/` | NaCl Box for signaling | Replace with TLS 1.3 FIPS |
| `client/internal/peer/` | Direct peer connections | Route through DTLS wrapper |
| New: `client/internal/fips/` | N/A | DTLS manager, cipher config, FIPS mode detection |

### Management Server

| File/Area | Current | Change |
|-----------|---------|--------|
| `management/server/` | TLS 1.3 (any ciphers) | Restrict to FIPS cipher suites |
| `util/crypt/` | AES-256-GCM (stdlib) | Use FIPS crypto module |
| gRPC config | Default TLS config | Explicit FIPS cipher list |

### Signal Server

| File/Area | Current | Change |
|-----------|---------|--------|
| `signal/` | NaCl Box encryption | Replace with TLS 1.3 FIPS for signaling |
| Message encryption | XSalsa20-Poly1305 | AES-256-GCM with FIPS module |

### Relay Server

| File/Area | Current | Change |
|-----------|---------|--------|
| `relay/` | QUIC/TLS 1.3 | Configure FIPS-only cipher suites |
| `relay/server/` | Default TLS config | Restrict to P-384 + AES-256-GCM |

### New Configuration Schema

```yaml
# netbird config
fips:
  enabled: true
  mode: "native"  # or "openssl"
  strict: true    # fail if FIPS unavailable
  cipher_suite: "TLS_AES_256_GCM_SHA384"
  min_tls_version: "1.3"
  allowed_curves:
    - "P-384"

dtls:
  min_version: "1.3"
  mtu: 1350
  session_timeout: 3600
```

---

## Go FIPS Module Integration

### Dual Module Support

Support both native Go FIPS and OpenSSL-based FIPS modules via build tags.

### Mode 1: Native Go FIPS (Go 1.24+)

```go
// Build tag: //go:build !openssl_fips

import "crypto/fips140"

func init() {
    if !fips140.Enabled() {
        log.Fatal("FIPS mode required but not enabled")
    }
}
```

Build command:
```bash
GODEBUG=fips140=on go build -o netbird-fips ./client
```

### Mode 2: OpenSSL FIPS

```go
// Build tag: //go:build openssl_fips

// Uses OpenSSL via cgo
// Requires: libssl-dev with FIPS module
```

Build command:
```bash
CGO_ENABLED=1 go build -tags openssl_fips -o netbird-fips-openssl ./client
```

### Abstraction Layer

```
┌─────────────────────────────────────────┐
│         NetBird Crypto Interface        │
│  (internal/fips/crypto.go)              │
├─────────────────────────────────────────┤
│  - Encrypt(plaintext) → ciphertext      │
│  - Decrypt(ciphertext) → plaintext      │
│  - NewTLSConfig() → *tls.Config         │
│  - NewDTLSConfig() → *dtls.Config       │
│  - ValidateFIPSMode() → error           │
└──────────────┬──────────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌─────────────┐  ┌─────────────┐
│ Native Go   │  │ OpenSSL     │
│ FIPS Module │  │ FIPS Module │
│ (go1.24+)   │  │ (cgo)       │
└─────────────┘  └─────────────┘
```

### Startup Validation

1. Verify FIPS mode is active
2. Run cryptographic self-tests (required by FIPS 140-3)
3. Fail fast with clear error if FIPS not available
4. Log FIPS module version and certificate number

---

## Key Management

### Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                      Root of Trust                               │
├─────────────────────────────────────────────────────────────────┤
│  Management Server CA                                            │
│  - ECDSA P-384 key pair                                         │
│  - Signs all server and client certificates                     │
│  - Stored encrypted at rest (AES-256-GCM)                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │ Server     │  │ Client     │  │ Client     │
     │ Cert       │  │ Cert A     │  │ Cert B     │
     │ (P-384)    │  │ (P-384)    │  │ (P-384)    │
     └────────────┘  └────────────┘  └────────────┘
```

### Key Types

| Key | Algorithm | Purpose | Storage |
|-----|-----------|---------|---------|
| CA Private Key | ECDSA P-384 | Signs certs | Encrypted file or HSM |
| Server TLS Key | ECDSA P-384 | Management/Signal/Relay TLS | Encrypted file |
| Client DTLS Key | ECDSA P-384 | Peer-to-peer DTLS sessions | Memory + encrypted config |
| WireGuard Key | Curve25519 | Inner tunnel (existing) | Memory + encrypted config |
| Database Key | AES-256 | Encrypt data at rest | Environment variable or secret manager |

### Key Generation

All keys generated using FIPS-approved DRBG:

```go
import "crypto/rand"  // FIPS module provides compliant RNG

privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
```

### Key Rotation Schedule

| Key Type | Rotation Period | Method |
|----------|-----------------|--------|
| DTLS session keys | Per session | Ephemeral ECDHE |
| Client certificates | 1 year (configurable) | Auto-renewal |
| CA certificate | 5-10 years | Manual with migration |
| Database encryption key | Manual | Re-encryption support |

### HSM Support (Optional)

For high-security deployments:
- PKCS#11 interface for CA key storage
- Compatible with AWS CloudHSM, Azure Dedicated HSM, on-prem HSMs
- Build flag: `-tags hsm`

---

## Compliance Mapping

### FIPS 140-3 Compliance Matrix

| FIPS 140-3 Requirement | How NetBird-FIPS Meets It |
|------------------------|---------------------------|
| **Approved Algorithms Only** | AES-256-GCM, ECDHE P-384, ECDSA P-384, SHA-384 - all NIST approved |
| **Validated Module** | Uses Go FIPS module (CMVP pending) or OpenSSL FIPS module (validated) |
| **Self-Tests at Startup** | FIPS module runs power-on self-tests; NetBird verifies FIPS mode active |
| **Key Management** | Keys generated via FIPS-approved DRBG (SP 800-90A) |
| **Module Boundaries** | Crypto operations isolated in `internal/fips/` package |
| **No Bypass** | Config option `fips.enabled: true` enforces FIPS-only paths; non-FIPS paths disabled |
| **Zeroization** | Keys cleared from memory on session termination |

### NIST SP 800-171 Rev 3 Compliance Matrix

| Control ID | Requirement | NetBird-FIPS Implementation |
|------------|-------------|----------------------------|
| **3.1.13** | Encrypt CUI on mobile devices | DTLS 1.3 + WireGuard encrypts all tunnel traffic |
| **3.1.16** | Encrypt CUI in transit | DTLS 1.3 AES-256-GCM on untrusted networks |
| **3.1.17** | Protect authenticity of communications | ECDSA P-384 signatures, mutual TLS authentication |
| **3.13.8** | Implement cryptographic mechanisms | FIPS 140-3 validated modules for all crypto |
| **3.13.10** | Establish and manage cryptographic keys | P-384 key hierarchy, FIPS-approved generation |
| **3.13.11** | Employ FIPS-validated cryptography | Mandatory FIPS mode, startup validation |

### Algorithm Reference Table

| Function | Algorithm | FIPS Reference | Strength |
|----------|-----------|----------------|----------|
| Key Exchange | ECDHE P-384 | SP 800-56A Rev 3 | 192-bit equivalent |
| Bulk Encryption | AES-256-GCM | FIPS 197, SP 800-38D | 256-bit |
| Digital Signature | ECDSA P-384 | FIPS 186-5 | 192-bit equivalent |
| Hashing | SHA-384 | FIPS 180-4 | 192-bit |
| Random Generation | CTR_DRBG | SP 800-90A | FIPS approved |

### Defense-in-Depth Documentation

```
CUI Data Protection Layers:
─────────────────────────────────────────────
Layer 1: Application-level encryption (if any)
Layer 2: WireGuard tunnel (Curve25519 + ChaCha20-Poly1305)
         └─ Not FIPS, but adds cryptographic depth
Layer 3: DTLS 1.3 tunnel (P-384 + AES-256-GCM)
         └─ FIPS 140-3 validated - PRIMARY COMPLIANCE LAYER
Layer 4: Physical/network security controls
─────────────────────────────────────────────

Auditor Note: Layer 3 (DTLS 1.3) is the FIPS compliance
boundary. Layer 2 (WireGuard) provides additional security
but is not claimed for FIPS compliance purposes.
```

---

## Build and Deployment

### Build Matrix

| Platform | Native Go FIPS | OpenSSL FIPS | Notes |
|----------|----------------|--------------|-------|
| Linux amd64 | ✅ | ✅ | Primary target |
| Linux arm64 | ✅ | ✅ | Raspberry Pi, AWS Graviton |
| Windows amd64 | ✅ | ⚠️ Complex | OpenSSL requires extra setup |
| macOS amd64/arm64 | ✅ | ⚠️ Complex | For development |
| FreeBSD | ✅ | ❌ | Native only |

### Build Commands

**Native Go FIPS**:
```bash
GODEBUG=fips140=on go build \
  -ldflags "-X main.fipsMode=native" \
  -o netbird-fips \
  ./client
```

**OpenSSL FIPS**:
```bash
CGO_ENABLED=1 go build \
  -tags openssl_fips \
  -ldflags "-X main.fipsMode=openssl" \
  -o netbird-fips-openssl \
  ./client
```

**Server Components**:
```bash
GODEBUG=fips140=on go build -o management-fips ./management
GODEBUG=fips140=on go build -o signal-fips ./signal
GODEBUG=fips140=on go build -o relay-fips ./relay
```

### Docker Image

```dockerfile
# Dockerfile.fips
FROM golang:1.25 AS builder

ENV GODEBUG=fips140=on
WORKDIR /src
COPY . .
RUN go build -o /netbird-fips ./client

FROM gcr.io/distroless/static-debian12
COPY --from=builder /netbird-fips /netbird
ENTRYPOINT ["/netbird"]
```

### Deployment Checklist

**Pre-Deployment**:
- [ ] Verify FIPS module certificate/validation status
- [ ] Generate CA certificate (P-384)
- [ ] Configure DNS for management server
- [ ] Provision server TLS certificates

**Server Deployment**:
- [ ] Deploy management-fips with FIPS config
- [ ] Deploy signal-fips with FIPS config
- [ ] Deploy relay-fips with FIPS config
- [ ] Verify FIPS mode in logs: "FIPS 140-3 mode: enabled"

**Client Deployment**:
- [ ] Distribute netbird-fips binary
- [ ] Configure management server URL
- [ ] Enroll client (receives DTLS certificate)
- [ ] Verify FIPS mode: `netbird status --fips`

### Configuration Example

```yaml
# /etc/netbird/config.yaml
fips:
  enabled: true
  mode: "native"  # or "openssl"
  strict: true    # fail if FIPS unavailable

tls:
  min_version: "1.3"
  cipher_suites:
    - "TLS_AES_256_GCM_SHA384"
  curves:
    - "P-384"

dtls:
  min_version: "1.3"
  cipher_suites:
    - "TLS_AES_256_GCM_SHA384"
  mtu: 1350
```

---

## Testing Strategy

### Test Categories

| Category | Purpose | Tools/Approach |
|----------|---------|----------------|
| FIPS Validation | Verify FIPS mode active | Startup self-tests, `netbird status --fips` |
| Cipher Compliance | Confirm only FIPS ciphers used | TLS/DTLS handshake inspection |
| Functional | Ensure VPN features work | Existing test suite + FIPS cases |
| Performance | Measure overhead | Throughput/latency benchmarks |
| Interoperability | Mixed FIPS/non-FIPS | Verify rejection of non-FIPS peers |

### Automated Tests

```go
// fips_test.go

func TestFIPSModeEnabled(t *testing.T) {
    if !fips.Enabled() {
        t.Fatal("FIPS mode not enabled")
    }
}

func TestOnlyFIPSCipherSuites(t *testing.T) {
    config := NewDTLSConfig()
    for _, suite := range config.CipherSuites {
        if !isApprovedCipher(suite) {
            t.Errorf("Non-FIPS cipher suite: %v", suite)
        }
    }
}

func TestRejectNonFIPSPeer(t *testing.T) {
    // FIPS client must reject connection from
    // peer offering non-FIPS ciphers
}

func TestP384OnlyKeyExchange(t *testing.T) {
    // Verify P-256 and other curves rejected
}
```

### Manual Verification

```bash
# 1. Verify FIPS mode in binary
$ netbird version --fips
NetBird v0.XX.X-fips
FIPS Mode: enabled (native)
FIPS Module: Go Cryptographic Module v1.0.0
CMVP Certificate: A6650

# 2. Capture and inspect DTLS handshake
$ tcpdump -i eth0 -w handshake.pcap port 51820
$ wireshark handshake.pcap
# Verify: TLS_AES_256_GCM_SHA384, curve P-384

# 3. Verify no non-FIPS fallback
$ netbird connect --fips-strict
# Should fail if FIPS unavailable

# 4. Check server cipher configuration
$ openssl s_client -connect mgmt.example.com:443 \
    -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384
# Should succeed

$ openssl s_client -connect mgmt.example.com:443 \
    -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
# Should be rejected
```

### Compliance Evidence Package

```
evidence/
├── fips-module-certificate.pdf    # CMVP validation cert
├── algorithm-test-vectors.log     # CAVP test results
├── cipher-suite-verification.pcap # Captured handshakes
├── config-review.yaml             # Production config
├── penetration-test-report.pdf    # Third-party security test
└── architecture-diagram.pdf       # System documentation
```

---

## References

### Standards

- [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) - Security Requirements for Cryptographic Modules
- [NIST SP 800-171 Rev 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final) - Protecting CUI in Nonfederal Systems
- [NIST SP 800-56A Rev 3](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final) - Key Establishment Schemes
- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) - GCM Mode
- [RFC 9147](https://datatracker.ietf.org/doc/html/rfc9147) - DTLS 1.3

### Go FIPS Resources

- [Go FIPS 140-3 Documentation](https://go.dev/doc/security/fips140)
- [Go FIPS Module Blog Post](https://go.dev/blog/fips140)
- [golang-fips/go Repository](https://github.com/golang-fips/go)

### CMVP Resources

- [CMVP Validated Modules List](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)
- [CMVP Modules In Process](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list)

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| CUI | Controlled Unclassified Information |
| CMVP | Cryptographic Module Validation Program |
| CAVP | Cryptographic Algorithm Validation Program |
| DRBG | Deterministic Random Bit Generator |
| DTLS | Datagram Transport Layer Security |
| ECDHE | Elliptic Curve Diffie-Hellman Ephemeral |
| ECDSA | Elliptic Curve Digital Signature Algorithm |
| FIPS | Federal Information Processing Standards |
| GCM | Galois/Counter Mode |
| HSM | Hardware Security Module |
| MTU | Maximum Transmission Unit |
| PSK | Pre-Shared Key |

---

## Appendix B: Change Log

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2026-01-16 | 1.0 | Architecture Team | Initial design |
