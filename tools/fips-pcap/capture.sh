#!/bin/bash
# FIPS DTLS Traffic Capture Script
#
# This script captures FIPS-encrypted DTLS traffic for analysis.
# Run with sudo for tcpdump permissions.
#
# Usage:
#   ./capture.sh              # Capture traffic on localhost
#   ./capture.sh eth0 5555    # Capture on eth0 port 5555

set -e

INTERFACE="${1:-lo0}"  # lo0 for macOS, lo for Linux
PORT="${2:-51821}"
PCAP_FILE="fips-dtls-capture-$(date +%Y%m%d-%H%M%S).pcap"
DURATION=30

echo "=========================================="
echo "FIPS DTLS Traffic Capture"
echo "=========================================="
echo "Interface: $INTERFACE"
echo "Port: $PORT"
echo "Output: $PCAP_FILE"
echo "Duration: ${DURATION}s"
echo ""

# Check for tcpdump
if ! command -v tcpdump &> /dev/null; then
    echo "Error: tcpdump not found"
    echo "Install with: brew install tcpdump (macOS) or apt install tcpdump (Linux)"
    exit 1
fi

# Check for Go
if ! command -v go &> /dev/null; then
    echo "Error: go not found"
    echo "Please install Go 1.24+"
    exit 1
fi

# Build the tool
echo "Building FIPS DTLS test tool..."
cd "$(dirname "$0")"
go build -o fips-pcap-tool .

echo ""
echo "Starting packet capture (requires sudo)..."
sudo tcpdump -i "$INTERFACE" -w "$PCAP_FILE" -s 0 "udp port $PORT" &
TCPDUMP_PID=$!
sleep 2

echo ""
echo "Starting FIPS DTLS server..."
./fips-pcap-tool -mode server -port "$PORT" &
SERVER_PID=$!
sleep 2

echo ""
echo "Running FIPS DTLS client..."
./fips-pcap-tool -mode client -addr "127.0.0.1:$PORT"

echo ""
echo "Cleaning up..."
kill $SERVER_PID 2>/dev/null || true
sleep 1
sudo kill $TCPDUMP_PID 2>/dev/null || true
sleep 1

echo ""
echo "=========================================="
echo "Capture complete!"
echo "=========================================="
echo ""
echo "Captured file: $PCAP_FILE"
echo ""
echo "To analyze the capture:"
echo "  tcpdump -r $PCAP_FILE -X"
echo "  wireshark $PCAP_FILE"
echo ""
echo "What to look for in Wireshark:"
echo "  1. Filter: udp.port == $PORT"
echo "  2. Right-click packet -> Decode As -> DTLS"
echo "  3. Check Cipher Suite in DTLS handshake"
echo "  4. Verify encrypted application data (not readable)"
echo ""
echo "Expected cipher suite: TLS_PSK_WITH_AES_128_GCM_SHA256"
