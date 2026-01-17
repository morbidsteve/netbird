//go:build fips

package openssl

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestInitFIPS(t *testing.T) {
	err := InitFIPS()
	if err != nil {
		t.Skipf("FIPS provider not available: %v", err)
	}

	if !IsFIPSEnabled() {
		t.Error("FIPS should be enabled after successful init")
	}
}

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Error("Version should not be empty")
	}
	t.Logf("OpenSSL version: %s", v)
}

func TestInitFIPSIdempotent(t *testing.T) {
	// First call
	err1 := InitFIPS()
	// Second call should return same result
	err2 := InitFIPS()

	if (err1 == nil) != (err2 == nil) {
		t.Error("InitFIPS should be idempotent")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *DTLSConfig
		wantErr error
	}{
		{
			name:    "empty PSK",
			config:  &DTLSConfig{},
			wantErr: ErrNoPSK,
		},
		{
			name: "PSK too short",
			config: &DTLSConfig{
				PSK: []byte("short"),
			},
			wantErr: ErrPSKTooShort,
		},
		{
			name: "valid config",
			config: &DTLSConfig{
				PSK:         []byte("0123456789abcdef"),
				PSKIdentity: []byte("test"),
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestDTLSHandshakeIntegration tests a full DTLS handshake between client and server.
func TestDTLSHandshakeIntegration(t *testing.T) {
	// Try to initialize FIPS - skip if not available
	if err := InitFIPS(); err != nil {
		t.Skipf("FIPS not available, skipping integration test: %v", err)
	}

	// Create UDP listener for server
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve server address: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("Failed to create server UDP conn: %v", err)
	}
	defer serverConn.Close()

	actualServerAddr := serverConn.LocalAddr().(*net.UDPAddr)
	t.Logf("Server listening on %s", actualServerAddr)

	// Shared PSK for both sides
	psk := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	identity := []byte("test-peer-identity")

	var wg sync.WaitGroup
	var serverErr, clientErr error
	var serverDTLS, clientDTLS *DTLSConn
	var serverCipher, clientCipher string

	// Server goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Wait for a client packet to establish "connection"
		buf := make([]byte, 4096)
		n, clientAddrUDP, readErr := serverConn.ReadFromUDP(buf)
		if readErr != nil {
			serverErr = readErr
			return
		}

		// Create a "connected" UDP socket for this client
		connectedServerConn, dialErr := net.DialUDP("udp", serverConn.LocalAddr().(*net.UDPAddr), clientAddrUDP)
		if dialErr != nil {
			serverErr = dialErr
			return
		}

		serverConfig := &DTLSConfig{
			PSK:              psk,
			PSKIdentity:      identity,
			IsServer:         true,
			MTU:              1400,
			HandshakeTimeout: 10 * time.Second,
		}

		serverDTLS, serverErr = NewDTLSConn(connectedServerConn, serverConfig)
		if serverErr != nil {
			return
		}

		// Write back the initial data we received to establish the connection
		_ = serverDTLS.bio.writeToRead(buf[:n])

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		serverErr = serverDTLS.Handshake(ctx)
		if serverErr != nil {
			return
		}

		serverCipher = serverDTLS.CipherSuite()
		t.Logf("Server handshake complete, cipher: %s", serverCipher)

		// Echo back any received data
		data := make([]byte, 1024)
		n, serverErr = serverDTLS.Read(data)
		if serverErr != nil {
			return
		}

		_, serverErr = serverDTLS.Write(data[:n])
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Client
	clientConn, err := net.DialUDP("udp", nil, actualServerAddr)
	if err != nil {
		t.Fatalf("Failed to create client UDP conn: %v", err)
	}
	defer clientConn.Close()

	clientConfig := &DTLSConfig{
		PSK:              psk,
		PSKIdentity:      identity,
		IsServer:         false,
		MTU:              1400,
		HandshakeTimeout: 10 * time.Second,
	}

	clientDTLS, clientErr = NewDTLSConn(clientConn, clientConfig)
	if clientErr != nil {
		t.Fatalf("Failed to create client DTLS conn: %v", clientErr)
	}
	defer func() {
		if clientDTLS != nil {
			clientDTLS.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientErr = clientDTLS.Handshake(ctx)
	if clientErr != nil {
		t.Fatalf("Client handshake failed: %v", clientErr)
	}

	clientCipher = clientDTLS.CipherSuite()
	t.Logf("Client handshake complete, cipher: %s", clientCipher)

	// Send test message
	testMsg := []byte("Hello, FIPS DTLS!")
	_, clientErr = clientDTLS.Write(testMsg)
	if clientErr != nil {
		t.Fatalf("Client write failed: %v", clientErr)
	}

	// Read echo response
	response := make([]byte, 1024)
	n, clientErr := clientDTLS.Read(response)
	if clientErr != nil {
		t.Fatalf("Client read failed: %v", clientErr)
	}

	wg.Wait()

	if serverErr != nil {
		t.Fatalf("Server error: %v", serverErr)
	}

	// Verify echo
	if !bytes.Equal(testMsg, response[:n]) {
		t.Errorf("Echo mismatch: sent %q, received %q", testMsg, response[:n])
	}

	// Verify FIPS cipher suite was used
	if clientCipher != "PSK-AES256-GCM-SHA384" && clientCipher != "PSK-AES128-GCM-SHA256" {
		t.Errorf("Non-FIPS cipher suite used: %s", clientCipher)
	}

	t.Logf("Integration test passed with cipher: %s", clientCipher)
}
