package dtlswrap

import (
	"context"
	"net"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	writeData []byte
	closed    bool
	localAddr net.Addr
	remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.closed {
		return 0, ErrClosed
	}
	n := copy(b, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	if m.closed {
		return 0, ErrClosed
	}
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockConn) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 54321}
}

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestWrapDisabled(t *testing.T) {
	mock := &mockConn{}
	cfg := DefaultConfig()
	cfg.Enabled = false

	wrapped, err := Wrap(context.Background(), mock, cfg)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Should return the original connection unchanged
	if wrapped != mock {
		t.Error("expected original connection when DTLS disabled")
	}
}

func TestWrapEnabled(t *testing.T) {
	mock := &mockConn{}
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FIPSRequired = false // Don't require FIPS for test
	cfg.PeerPublicKey = "abc123def456"
	cfg.LocalPublicKey = "xyz789uvw012"

	wrapped, err := Wrap(context.Background(), mock, cfg)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Should return wrapped connection
	if wrapped == mock {
		t.Error("expected wrapped connection, got original")
	}

	// Verify it's our Conn type
	dtlsConn, ok := wrapped.(*Conn)
	if !ok {
		t.Fatal("expected *Conn type")
	}

	if !dtlsConn.handshook {
		t.Error("expected handshake to complete")
	}
}

func TestConnReadWrite(t *testing.T) {
	mock := &mockConn{
		readData: []byte("hello from peer"),
	}
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FIPSRequired = false
	cfg.PeerPublicKey = "abc123def456"

	wrapped, err := Wrap(context.Background(), mock, cfg)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	// Test write
	writeData := []byte("hello to peer")
	n, err := wrapped.Write(writeData)
	if err != nil {
		t.Errorf("Write() error = %v", err)
	}
	if n != len(writeData) {
		t.Errorf("Write() n = %d, want %d", n, len(writeData))
	}

	// Test read
	readBuf := make([]byte, 100)
	n, err = wrapped.Read(readBuf)
	if err != nil {
		t.Errorf("Read() error = %v", err)
	}
	if string(readBuf[:n]) != "hello from peer" {
		t.Errorf("Read() = %q, want %q", readBuf[:n], "hello from peer")
	}
}

func TestConnClose(t *testing.T) {
	mock := &mockConn{}
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FIPSRequired = false
	cfg.PeerPublicKey = "abc123def456"

	wrapped, err := Wrap(context.Background(), mock, cfg)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	if err := wrapped.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Double close should be safe
	if err := wrapped.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}

	// Operations on closed connection should fail
	_, err = wrapped.Write([]byte("test"))
	if err != ErrClosed {
		t.Errorf("Write() on closed conn error = %v, want ErrClosed", err)
	}
}

func TestConnAddresses(t *testing.T) {
	localAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 51820}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 51820}

	mock := &mockConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FIPSRequired = false
	cfg.PeerPublicKey = "abc123def456"

	wrapped, err := Wrap(context.Background(), mock, cfg)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	if wrapped.LocalAddr().String() != localAddr.String() {
		t.Errorf("LocalAddr() = %v, want %v", wrapped.LocalAddr(), localAddr)
	}

	if wrapped.RemoteAddr().String() != remoteAddr.String() {
		t.Errorf("RemoteAddr() = %v, want %v", wrapped.RemoteAddr(), remoteAddr)
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

func TestHandshakeTimeout(t *testing.T) {
	mock := &mockConn{}
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.FIPSRequired = false
	cfg.HandshakeTimeout = 1 * time.Millisecond // Very short timeout
	cfg.PeerPublicKey = "abc123def456"

	// Use a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Wrap(ctx, mock, cfg)
	if err == nil {
		t.Error("expected error with canceled context")
	}
}
