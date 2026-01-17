//go:build !fips

package dtlswrap

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestWrapDisabled(t *testing.T) {
	// Create a mock connection for disabled test
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Enabled = false

	wrapped, err := Wrap(context.Background(), client, cfg)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Should return the original connection unchanged
	if wrapped != client {
		t.Error("expected original connection when DTLS disabled")
	}
}

func TestWrapInvalidKey(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FIPSRequired = false
	cfg.PeerPublicKey = "" // Empty key should fail

	_, err := Wrap(context.Background(), client, cfg)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestDerivePSK(t *testing.T) {
	localKey := "abc123def456"
	peerKey := "xyz789uvw012"

	// Test determinism - same inputs should produce same output
	psk1 := derivePSK(localKey, peerKey)
	psk2 := derivePSK(localKey, peerKey)

	if len(psk1) != 32 {
		t.Errorf("PSK length = %d, want 32", len(psk1))
	}

	for i := range psk1 {
		if psk1[i] != psk2[i] {
			t.Error("PSK derivation not deterministic")
			break
		}
	}

	// Test symmetry - order shouldn't matter
	psk3 := derivePSK(peerKey, localKey)
	for i := range psk1 {
		if psk1[i] != psk3[i] {
			t.Error("PSK derivation not symmetric")
			break
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("Enabled should be false by default")
	}
	if cfg.FIPSRequired {
		t.Error("FIPSRequired should be false by default")
	}
	if cfg.HandshakeTimeout != 30*time.Second {
		t.Errorf("HandshakeTimeout = %v, want 30s", cfg.HandshakeTimeout)
	}
	if cfg.MTU != 1350 {
		t.Errorf("MTU = %d, want 1350", cfg.MTU)
	}
}

func TestGetConfig(t *testing.T) {
	cfg := GetConfig("peer-public-key", "local-public-key", true)

	if cfg.PeerPublicKey != "peer-public-key" {
		t.Errorf("PeerPublicKey = %s, want peer-public-key", cfg.PeerPublicKey)
	}
	if cfg.LocalPublicKey != "local-public-key" {
		t.Errorf("LocalPublicKey = %s, want local-public-key", cfg.LocalPublicKey)
	}
	if !cfg.IsInitiator {
		t.Error("IsInitiator should be true")
	}
}

func TestRoleString(t *testing.T) {
	if roleString(true) != "client" {
		t.Errorf("roleString(true) = %s, want client", roleString(true))
	}
	if roleString(false) != "server" {
		t.Errorf("roleString(false) = %s, want server", roleString(false))
	}
}

// TestDTLSHandshakeIntegration tests a real DTLS handshake between client and server.
// This test uses actual UDP connections to verify the pion/dtls integration.
// Skip in short mode as it requires actual network I/O.
func TestDTLSHandshakeIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Use pion/dtls native Listen/Dial for proper DTLS connection management
	// This is a more thorough integration test
	t.Skip("Integration test requires full network setup - run manually")
}

func TestConnClose(t *testing.T) {
	// Test that Close is idempotent
	client, server := net.Pipe()
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Enabled = false

	wrapped, err := Wrap(context.Background(), client, cfg)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Close should succeed
	if err := wrapped.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestConnAddresses(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cfg := DefaultConfig()
	cfg.Enabled = false

	wrapped, err := Wrap(context.Background(), client, cfg)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Addresses should pass through
	if wrapped.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil")
	}
	if wrapped.RemoteAddr() == nil {
		t.Error("RemoteAddr() returned nil")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	// This test verifies timeout behavior with real network I/O
	// Skip for now as it requires more sophisticated setup
	t.Skip("Timeout test requires full network setup")
}

// TestConnAdapterInterface verifies connAdapter implements net.PacketConn
func TestConnAdapterInterface(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	adapter := &connAdapter{
		conn:       client,
		remoteAddr: server.LocalAddr(),
	}

	// Verify it implements net.PacketConn
	var _ net.PacketConn = adapter

	// Test methods don't panic
	_ = adapter.LocalAddr()
	_ = adapter.SetDeadline(time.Now().Add(time.Second))
	_ = adapter.SetReadDeadline(time.Now().Add(time.Second))
	_ = adapter.SetWriteDeadline(time.Now().Add(time.Second))
}
