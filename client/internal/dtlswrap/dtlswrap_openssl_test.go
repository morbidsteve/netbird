//go:build fips

package dtlswrap

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/netbirdio/netbird/internal/fips/openssl"
)

func TestWrapDisabled_OpenSSL(t *testing.T) {
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

func TestWrapInvalidKey_OpenSSL(t *testing.T) {
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

func TestDerivePSK_OpenSSL(t *testing.T) {
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

func TestDefaultConfig_OpenSSL(t *testing.T) {
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

func TestOpenSSLFIPSInit(t *testing.T) {
	err := openssl.InitFIPS()
	if err != nil {
		t.Skipf("OpenSSL FIPS not available: %v", err)
	}

	if !openssl.IsFIPSEnabled() {
		t.Error("FIPS should be enabled after successful init")
	}

	t.Logf("OpenSSL version: %s", openssl.Version())
}

func TestGetConfig_OpenSSL(t *testing.T) {
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

func TestRoleString_OpenSSL(t *testing.T) {
	if roleString(true) != "client" {
		t.Errorf("roleString(true) = %s, want client", roleString(true))
	}
	if roleString(false) != "server" {
		t.Errorf("roleString(false) = %s, want server", roleString(false))
	}
}
