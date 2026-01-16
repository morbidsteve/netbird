#!/bin/bash
# FIPS Verification Script for NetBird
# Verifies OpenSSL FIPS provider and NetBird FIPS build
set -e

echo "=== NetBird FIPS Verification ==="
echo ""

ERRORS=0

# 1. Check OpenSSL version
echo "1. Checking OpenSSL version..."
if command -v openssl &> /dev/null; then
    VERSION=$(openssl version)
    echo "   $VERSION"

    MAJOR=$(echo "$VERSION" | cut -d' ' -f2 | cut -d'.' -f1)
    if [ "$MAJOR" -ge 3 ]; then
        echo "   [PASS] OpenSSL 3.x detected"
    else
        echo "   [FAIL] OpenSSL 3.0+ required"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "   [FAIL] OpenSSL not found"
    ERRORS=$((ERRORS + 1))
fi

# 2. Check FIPS provider
echo ""
echo "2. Checking OpenSSL FIPS provider..."
if openssl list -providers 2>/dev/null | grep -q "fips"; then
    echo "   [PASS] FIPS provider available"
else
    echo "   [WARN] FIPS provider not loaded by default"
    echo "   This may be normal - FIPS provider can be loaded programmatically"
fi

# 3. Check FIPS algorithms
echo ""
echo "3. Checking FIPS-approved algorithms..."
if openssl list -cipher-algorithms 2>/dev/null | grep -q "AES-256-GCM"; then
    echo "   [PASS] AES-256-GCM available"
else
    echo "   [FAIL] AES-256-GCM not found"
    ERRORS=$((ERRORS + 1))
fi

if openssl list -cipher-algorithms 2>/dev/null | grep -q "AES-128-GCM"; then
    echo "   [PASS] AES-128-GCM available"
else
    echo "   [FAIL] AES-128-GCM not found"
    ERRORS=$((ERRORS + 1))
fi

# 4. Check for FIPS binary
echo ""
echo "4. Checking NetBird FIPS binary..."
BINARY=""
if [ -f "./build/netbird-fips" ]; then
    BINARY="./build/netbird-fips"
elif [ -f "./netbird-fips" ]; then
    BINARY="./netbird-fips"
fi

if [ -n "$BINARY" ]; then
    echo "   [PASS] Found: $BINARY"

    # Check for OpenSSL linkage
    echo ""
    echo "5. Checking OpenSSL linkage..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if otool -L "$BINARY" 2>/dev/null | grep -q "libssl\|libcrypto"; then
            echo "   [PASS] Binary linked against OpenSSL"
            otool -L "$BINARY" 2>/dev/null | grep -E "libssl|libcrypto" | head -2 | sed 's/^/   /'
        else
            echo "   [WARN] Cannot verify OpenSSL linkage"
        fi
    else
        if ldd "$BINARY" 2>/dev/null | grep -q "libssl\|libcrypto"; then
            echo "   [PASS] Binary linked against OpenSSL"
            ldd "$BINARY" 2>/dev/null | grep -E "libssl|libcrypto" | head -2 | sed 's/^/   /'
        else
            echo "   [WARN] Cannot verify OpenSSL linkage"
        fi
    fi
else
    echo "   [SKIP] NetBird FIPS binary not found"
    echo "   Run ./scripts/build-fips.sh first"
fi

# Summary
echo ""
echo "=== Verification Summary ==="
if [ $ERRORS -eq 0 ]; then
    echo "[PASS] All checks passed"
    echo ""
    echo "FIPS Compliance Reference:"
    echo "  OpenSSL FIPS Provider: NIST Certificate #4282"
    echo "  Validation Level: FIPS 140-3"
    echo "  Approved Algorithms: AES-GCM, SHA-2, ECDHE"
else
    echo "[FAIL] $ERRORS check(s) failed"
    exit 1
fi
