# FIPS 140-3 OpenSSL DTLS Integration Design

## Overview

Replace pion/dtls with OpenSSL 3.0 DTLS using the FIPS provider (Certificate #4282) to achieve FIPS 140-3 validated encryption for NetBird peer-to-peer connections.

## Architecture

**Data Flow:**
```
[Application Traffic]
        ↓
[WireGuard Tunnel - ChaCha20-Poly1305 (defense-in-depth)]
        ↓
[DTLS Wrapper - OpenSSL FIPS AES-256-GCM]  ← FIPS-validated layer
        ↓
[ICE/Relay Transport]
        ↓
[Network]
```

**Key Components:**
1. `internal/fips/openssl/` - cgo bindings to OpenSSL 3.0 DTLS
2. `internal/fips/openssl/fips_provider.go` - FIPS provider initialization
3. Modified `client/internal/dtlswrap/` - Uses OpenSSL instead of pion/dtls
4. Build tags for optional FIPS builds (`//go:build fips`)

**Crypto Algorithms (FIPS-approved):**
- Key Exchange: ECDHE with P-256 or P-384
- Encryption: AES-256-GCM
- MAC: GMAC (part of GCM)
- PRF: SHA-384

**FIPS Validation Reference:**
- OpenSSL 3.0 FIPS Provider: Certificate #4282

## OpenSSL cgo Bindings

**Package Structure:**
```
internal/fips/openssl/
├── openssl.go          # cgo bindings, FIPS init
├── dtls.go             # DTLS connection wrapper
├── config.go           # TLS/DTLS configuration
├── errors.go           # OpenSSL error handling
└── openssl_test.go     # Tests with FIPS verification
```

**FIPS Provider Initialization:**
```go
// #cgo pkg-config: openssl
// #include <openssl/provider.h>
// #include <openssl/evp.h>
// #include <openssl/ssl.h>
import "C"

func InitFIPS() error {
    // Load FIPS provider
    fips := C.OSSL_PROVIDER_load(nil, C.CString("fips"))
    if fips == nil {
        return errors.New("failed to load OpenSSL FIPS provider")
    }

    // Load base provider for non-crypto operations
    C.OSSL_PROVIDER_load(nil, C.CString("base"))

    // Verify FIPS mode is active
    if C.EVP_default_properties_is_fips_enabled(nil) != 1 {
        return errors.New("FIPS mode not enabled")
    }
    return nil
}
```

**DTLS Connection Interface:**
```go
type DTLSConn struct {
    ssl    *C.SSL
    ctx    *C.SSL_CTX
    conn   net.Conn      // underlying UDP connection
    psk    []byte        // pre-shared key
}

func (d *DTLSConn) Read(b []byte) (int, error)
func (d *DTLSConn) Write(b []byte) (int, error)
func (d *DTLSConn) Close() error
func (d *DTLSConn) Handshake() error
```

## Integration with dtlswrap

**Modified Package Structure:**
```
client/internal/dtlswrap/
├── dtlswrap.go              # Interface + build routing
├── dtlswrap_pion.go         # //go:build !fips (current pion/dtls)
├── dtlswrap_openssl.go      # //go:build fips (OpenSSL FIPS)
└── dtlswrap_test.go         # Tests both implementations
```

**Common Interface (dtlswrap.go):**
```go
// Config remains the same as current implementation
type Config struct {
    Enabled        bool
    PeerPublicKey  string
    LocalPublicKey string
    IsInitiator    bool
    MTU            int
}

// Wrap signature unchanged - implementation selected by build tag
func Wrap(ctx context.Context, conn net.Conn, cfg Config) (net.Conn, error)
func GetConfig(peerKey, localKey string, isInitiator bool) Config
```

**OpenSSL Implementation (dtlswrap_openssl.go):**
```go
//go:build fips

func Wrap(ctx context.Context, conn net.Conn, cfg Config) (net.Conn, error) {
    if !cfg.Enabled {
        return conn, nil
    }

    psk := derivePSK(cfg.LocalPublicKey, cfg.PeerPublicKey)

    dtlsConn, err := openssl.NewDTLSConn(conn, &openssl.Config{
        PSK:           psk,
        PSKIdentity:   []byte(cfg.LocalPublicKey),
        IsServer:      !cfg.IsInitiator,
        CipherSuites:  []string{"TLS_AES_256_GCM_SHA384"},
        MinVersion:    openssl.DTLSv1_2,
    })
    if err != nil {
        return nil, fmt.Errorf("OpenSSL DTLS setup failed: %w", err)
    }

    return dtlsConn, dtlsConn.Handshake()
}
```

**Backward Compatibility:**
- Default build (no tags): Uses pion/dtls (current behavior)
- FIPS build (`go build -tags fips`): Uses OpenSSL FIPS
- Runtime detection: `fips.IsEnabled()` reports which backend is active

## Build System & Deployment

**Build Commands:**
```bash
# Standard build (pion/dtls, no FIPS)
go build ./...

# FIPS build (OpenSSL FIPS provider)
CGO_ENABLED=1 go build -tags fips ./...
```

**Dockerfile for FIPS Builds:**
```dockerfile
FROM golang:1.24-bookworm AS builder

# Install OpenSSL 3.0 with FIPS provider
RUN apt-get update && apt-get install -y \
    libssl-dev \
    openssl \
    pkg-config

# Verify FIPS provider exists
RUN openssl list -providers | grep fips

WORKDIR /src
COPY . .

# Build with FIPS tag
RUN CGO_ENABLED=1 go build -tags fips -o netbird-fips ./client

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 openssl
COPY --from=builder /src/netbird-fips /usr/local/bin/

# Configure OpenSSL FIPS mode
COPY openssl-fips.cnf /etc/ssl/openssl.cnf
```

**OpenSSL FIPS Configuration (openssl-fips.cnf):**
```ini
config_diagnostics = 1
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[fips_sect]
activate = 1

[base_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
```

**CI/CD Matrix:**
| Build Type | Tags | CGO | OpenSSL | Use Case |
|------------|------|-----|---------|----------|
| Standard | none | off | no | Community/non-federal |
| FIPS | fips | on | 3.0+ | Federal/CUI |

## Testing & Verification

**Test Categories:**

**1. Unit Tests (internal/fips/openssl/):**
```go
func TestFIPSProviderLoads(t *testing.T) {
    err := openssl.InitFIPS()
    require.NoError(t, err)
    require.True(t, openssl.IsFIPSEnabled())
}

func TestDTLSHandshake_FIPS(t *testing.T) {
    // Server/client handshake with FIPS ciphers only
    // Verify negotiated cipher is AES-256-GCM
}

func TestNonFIPSCipherRejected(t *testing.T) {
    // Ensure ChaCha20-Poly1305 is rejected in FIPS mode
}
```

**2. Integration Tests (client/internal/dtlswrap/):**
```go
//go:build fips

func TestDTLSWrap_OpenSSL(t *testing.T) {
    // Full peer-to-peer connection through DTLS wrapper
    // Verify data integrity and encryption
}
```

**3. FIPS Verification Script (scripts/verify-fips.sh):**
```bash
#!/bin/bash
set -e

echo "Verifying OpenSSL FIPS provider..."
openssl list -providers | grep -q "fips" || exit 1

echo "Verifying FIPS algorithms..."
openssl list -cipher-algorithms | grep -q "AES-256-GCM" || exit 1

echo "Testing NetBird FIPS mode..."
./netbird-fips version --fips-status | grep -q "FIPS: enabled" || exit 1

echo "Capturing test traffic..."
# Run pcap capture and verify cipher suite in Wireshark

echo "FIPS verification complete"
```

**4. Runtime Verification:**
```go
// Added to client startup
func main() {
    if fips.IsEnabled() {
        log.Info("FIPS 140-3 mode: ENABLED (OpenSSL Certificate #4282)")
        log.Infof("FIPS provider: %s", fips.ProviderVersion())
    }
}
```

## Compliance Documentation

Required documentation for federal deployments:
- `docs/fips-compliance-statement.md` - References Certificate #4282
- `docs/fips-deployment-guide.md` - Installation with FIPS provider
- Audit logging: FIPS mode status logged at startup

## Dependencies

**Build-time:**
- OpenSSL 3.0+ development libraries (`libssl-dev`)
- pkg-config
- C compiler (gcc/clang)

**Runtime:**
- OpenSSL 3.0+ (`libssl3`)
- OpenSSL FIPS provider module (`fips.so`)
- FIPS configuration file (`openssl.cnf`)

## Security Considerations

1. **Defense in Depth:** WireGuard provides inner encryption; DTLS provides FIPS-validated outer encryption
2. **Key Derivation:** PSK derived from WireGuard public keys using SHA-256
3. **Certificate Reference:** OpenSSL FIPS Provider Certificate #4282
4. **Algorithm Constraints:** FIPS mode enforces approved algorithms only
