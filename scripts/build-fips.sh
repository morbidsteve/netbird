#!/bin/bash
# FIPS Build Script for NetBird
# Builds NetBird with OpenSSL FIPS provider (Certificate #4282)
set -e

echo "=== NetBird FIPS Build ==="
echo ""

# Check for OpenSSL 3.0+
if ! command -v openssl &> /dev/null; then
    echo "Error: openssl not found"
    echo "Install with: brew install openssl@3 (macOS) or apt install libssl-dev (Debian)"
    exit 1
fi

OPENSSL_VERSION=$(openssl version | cut -d' ' -f2)
MAJOR_VERSION=$(echo "$OPENSSL_VERSION" | cut -d'.' -f1)

if [ "$MAJOR_VERSION" -lt 3 ]; then
    echo "Error: OpenSSL 3.0+ required, found $OPENSSL_VERSION"
    exit 1
fi

echo "OpenSSL version: $OPENSSL_VERSION"

# Set up pkg-config path for OpenSSL on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    if [ -d "/opt/homebrew/opt/openssl@3" ]; then
        export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:$PKG_CONFIG_PATH"
    elif [ -d "/usr/local/opt/openssl@3" ]; then
        export PKG_CONFIG_PATH="/usr/local/opt/openssl@3/lib/pkgconfig:$PKG_CONFIG_PATH"
    fi
fi

# Check for CGO requirements
echo ""
echo "Checking CGO requirements..."

if ! command -v cc &> /dev/null && ! command -v gcc &> /dev/null; then
    echo "Warning: C compiler not found. CGO may fail."
    echo "Install with: xcode-select --install (macOS) or apt install build-essential (Debian)"
fi

# Build output directory
OUTPUT_DIR="${OUTPUT_DIR:-./build}"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "Building NetBird client with FIPS support..."
echo "Output directory: $OUTPUT_DIR"
echo ""

# Build the client
CGO_ENABLED=1 go build -tags fips -o "$OUTPUT_DIR/netbird-fips" ./client

echo ""
echo "Build complete!"
echo ""
echo "Binary: $OUTPUT_DIR/netbird-fips"
echo ""
echo "To verify FIPS mode:"
echo "  ./scripts/verify-fips.sh"
echo ""
echo "FIPS Reference:"
echo "  OpenSSL FIPS Provider: Certificate #4282"
echo "  Cipher Suite: PSK-AES256-GCM-SHA384"
