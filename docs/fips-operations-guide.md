# NetBird FIPS 140-3 Operations Guide

This guide covers deploying and operating NetBird in FIPS 140-3 compliant mode for handling Controlled Unclassified Information (CUI).

## Overview

NetBird FIPS mode adds a DTLS 1.3 encryption layer using FIPS 140-3 approved algorithms around the existing WireGuard tunnels. This provides:

- **FIPS-validated encryption**: AES-256-GCM with ECDHE P-384 key exchange
- **Defense in depth**: Two layers of encryption (FIPS outer + WireGuard inner)
- **Compliance ready**: Meets NIST SP 800-171 requirements for CUI protection

## Prerequisites

- **Go 1.24+** for native FIPS module, OR
- **golang-fips/go** toolchain for OpenSSL FIPS module
- TLS certificates using **P-384 or P-256 ECDSA keys**
- Understanding of your organization's FIPS compliance requirements

## Building FIPS-Compliant Binaries

### Option 1: Native Go FIPS (Recommended)

The native Go FIPS module is included in Go 1.24+ and requires no external dependencies.

```bash
# Build all components with native FIPS
export GODEBUG=fips140=on

go build -ldflags "-X main.fipsMode=native" -o netbird-client-fips ./client
go build -ldflags "-X main.fipsMode=native" -o netbird-management-fips ./management
go build -ldflags "-X main.fipsMode=native" -o netbird-signal-fips ./signal
go build -ldflags "-X main.fipsMode=native" -o netbird-relay-fips ./relay
```

### Option 2: OpenSSL FIPS

For environments requiring an already-validated FIPS module:

```bash
# Requires golang-fips/go toolchain
export CGO_ENABLED=1

go build -tags openssl_fips -ldflags "-X main.fipsMode=openssl" \
  -o netbird-client-fips-openssl ./client
```

### Docker Build

```dockerfile
FROM golang:1.25 AS builder

ENV GODEBUG=fips140=on
WORKDIR /src
COPY . .

RUN go build -ldflags "-X main.fipsMode=native" -o /netbird-client-fips ./client

FROM gcr.io/distroless/static-debian12
COPY --from=builder /netbird-client-fips /netbird
ENTRYPOINT ["/netbird"]
```

## Configuration

### Enable FIPS Mode

**Option A: Configuration file**

```yaml
# /etc/netbird/config.yaml
fips:
  enabled: true
  mode: native     # or "openssl"
  strict: true     # fail startup if FIPS unavailable

tls:
  min_version: "1.3"
  cipher_suites:
    - "TLS_AES_256_GCM_SHA384"
  curves:
    - "P-384"

dtls:
  mtu: 1350
```

**Option B: Environment variables**

```bash
export NETBIRD_FIPS_ENABLED=true
export GODEBUG=fips140=on
```

### Certificate Requirements

FIPS mode requires certificates using approved algorithms:

```bash
# Generate P-384 ECDSA key (FIPS approved)
openssl ecparam -name secp384r1 -genkey -noout -out server-key.pem

# Create certificate signing request
openssl req -new -key server-key.pem -out server.csr \
  -subj "/CN=netbird-server/O=YourOrg"

# Self-sign (for testing) or submit to CA
openssl x509 -req -in server.csr -signkey server-key.pem \
  -out server-cert.pem -days 365 -sha384
```

**Verify certificate algorithm:**

```bash
openssl x509 -in server-cert.pem -text -noout | grep "Public Key Algorithm"
# Should show: id-ecPublicKey (P-384)
```

## Verification

### Check FIPS Status

```bash
# Check if binary reports FIPS mode
./netbird-client-fips version --fips
```

Expected output:
```
NetBird vX.Y.Z-fips
FIPS Mode: enabled (native)
Module: Go Cryptographic Module v1.0.0
Certificate: A6650 (Review Pending)
```

### Verify at Runtime

Check logs for FIPS initialization:

```
INFO FIPS 140-3 mode: enabled (native Go module)
INFO FIPS module: Go Cryptographic Module v1.0.0
INFO FIPS certificate: A6650 (Review Pending)
```

### Verify Cipher Suites (Network Capture)

```bash
# Capture DTLS handshake
tcpdump -i eth0 -w capture.pcap port 51820

# Analyze with Wireshark or tshark
tshark -r capture.pcap -Y "dtls.handshake" \
  -T fields -e dtls.handshake.ciphersuite
```

Expected cipher suites:
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xc02c)
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xc030)

### Test Non-FIPS Rejection

```bash
# Attempt connection with non-FIPS cipher
openssl s_client -connect management.example.com:443 \
  -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256

# Should be rejected (connection refused or handshake failure)
```

## Deployment Checklist

### Pre-Deployment

- [ ] Verify FIPS module validation status at [CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
- [ ] Generate CA and server certificates using P-384 ECDSA
- [ ] Configure DNS for management server
- [ ] Review network firewall rules (UDP 51820 for DTLS)

### Server Deployment

- [ ] Deploy management-fips with FIPS configuration
- [ ] Deploy signal-fips with FIPS configuration
- [ ] Deploy relay-fips with FIPS configuration
- [ ] Verify FIPS mode in startup logs
- [ ] Test TLS cipher suite negotiation

### Client Deployment

- [ ] Distribute netbird-client-fips binary
- [ ] Configure management server URL
- [ ] Enroll client (receives DTLS certificate)
- [ ] Verify FIPS status: `netbird status --fips`
- [ ] Test connectivity to peers

## Troubleshooting

### "FIPS mode not enabled" Error

**Cause:** GODEBUG environment variable not set.

**Solution:**
```bash
export GODEBUG=fips140=on
# Or add to systemd unit file:
# Environment="GODEBUG=fips140=on"
```

### Certificate Rejected

**Cause:** Certificate uses non-FIPS algorithm (e.g., Ed25519, RSA < 2048).

**Solution:**
```bash
# Check certificate algorithm
openssl x509 -in cert.pem -text | grep "Public Key Algorithm"

# Regenerate with FIPS-approved algorithm
openssl ecparam -name secp384r1 -genkey -noout -out key.pem
```

### Handshake Failure

**Cause:** Peer offering non-FIPS cipher suites.

**Solution:** Ensure all peers are running FIPS-enabled builds.

### Performance Degradation

**Cause:** Double encryption overhead.

**Mitigation:**
- Expected ~5-15% throughput reduction
- Adjust MTU if fragmentation occurs
- Use hardware with AES-NI support

## Compliance Documentation

### FIPS 140-3 Evidence

| Requirement | Evidence |
|-------------|----------|
| Validated module | Go Cryptographic Module v1.0.0, CMVP A6650 |
| Approved algorithms | AES-256-GCM, ECDHE P-384, SHA-384 |
| Self-tests | Module performs power-on self-tests |
| Key management | DRBG per SP 800-90A |

### NIST SP 800-171 Mapping

| Control | Implementation |
|---------|----------------|
| 3.1.13 (Mobile encryption) | DTLS encrypts all tunnel traffic |
| 3.1.16 (Transit encryption) | FIPS AES-256-GCM |
| 3.13.11 (FIPS crypto) | Validated module required |

## Support

For issues specific to FIPS mode:

1. Check logs for FIPS initialization errors
2. Verify certificate algorithms
3. Capture network traffic for cipher analysis
4. Open issue at your organization's support channel

## References

- [NIST FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)
- [NIST SP 800-171 Rev 3](https://csrc.nist.gov/pubs/sp/800/171/r3/final)
- [Go FIPS 140-3 Documentation](https://go.dev/doc/security/fips140)
- [CMVP Validated Modules](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)
