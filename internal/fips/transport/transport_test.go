package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// generateTestCertP384 creates a test certificate using P-384 (FIPS approved).
func generateTestCertP384() (*tls.Certificate, *x509.CertPool, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test FIPS Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	pool := x509.NewCertPool()
	parsedCert, _ := x509.ParseCertificate(certDER)
	pool.AddCert(parsedCert)

	return cert, pool, nil
}

func TestNewTransport(t *testing.T) {
	cert, pool, err := generateTestCertP384()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	cfg := Config{
		LocalAddr:   "127.0.0.1:0",
		Certificate: cert,
		RootCAs:     pool,
		ClientCAs:   pool,
		IsServer:    true,
		MTU:         1350,
	}

	transport, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer transport.Close()

	if transport.tlsConfig == nil {
		t.Error("expected TLS config to be set")
	}

	if transport.fipsConfig.MTU != 1350 {
		t.Errorf("MTU = %d, want 1350", transport.fipsConfig.MTU)
	}
}

func TestNewTransportDefaults(t *testing.T) {
	cfg := Config{
		LocalAddr: "127.0.0.1:0",
	}

	transport, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer transport.Close()

	if transport.fipsConfig.MTU != 1350 {
		t.Errorf("default MTU = %d, want 1350", transport.fipsConfig.MTU)
	}

	if transport.fipsConfig.HandshakeTimeout != 30*time.Second {
		t.Errorf("default handshake timeout = %v, want 30s", transport.fipsConfig.HandshakeTimeout)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MTU != 1350 {
		t.Errorf("MTU = %d, want 1350", cfg.MTU)
	}

	if cfg.HandshakeTimeout != 30*time.Second {
		t.Errorf("HandshakeTimeout = %v, want 30s", cfg.HandshakeTimeout)
	}

	if !cfg.RequireClientCert {
		t.Error("RequireClientCert should be true by default")
	}
}

func TestTransportListen(t *testing.T) {
	cert, pool, err := generateTestCertP384()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	cfg := Config{
		LocalAddr:   "127.0.0.1:0",
		Certificate: cert,
		RootCAs:     pool,
		ClientCAs:   pool,
		IsServer:    true,
	}

	transport, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer transport.Close()

	ctx := context.Background()
	if err := transport.Listen(ctx); err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	addr := transport.LocalAddr()
	if addr == nil {
		t.Fatal("expected local address after listen")
	}
	t.Logf("Listening on %s", addr)
}

func TestTransportClose(t *testing.T) {
	cfg := Config{
		LocalAddr: "127.0.0.1:0",
	}

	transport, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	// Close should work on non-listening transport
	if err := transport.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Double close should be safe
	if err := transport.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}
}

func TestTransportClosedErrors(t *testing.T) {
	cfg := Config{
		LocalAddr: "127.0.0.1:0",
	}

	transport, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}

	transport.Close()

	ctx := context.Background()

	// Listen should fail on closed transport
	if err := transport.Listen(ctx); err != ErrTransportClosed {
		t.Errorf("Listen() error = %v, want ErrTransportClosed", err)
	}

	// Dial should fail on closed transport
	if _, err := transport.Dial(ctx, "127.0.0.1:12345"); err != ErrTransportClosed {
		t.Errorf("Dial() error = %v, want ErrTransportClosed", err)
	}
}

func TestTransportGetConnection(t *testing.T) {
	cfg := Config{
		LocalAddr: "127.0.0.1:0",
	}

	transport, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create transport: %v", err)
	}
	defer transport.Close()

	// No connections initially
	conn, ok := transport.GetConnection("127.0.0.1:12345")
	if ok || conn != nil {
		t.Error("expected no connection initially")
	}

	if transport.ConnectionCount() != 0 {
		t.Errorf("ConnectionCount = %d, want 0", transport.ConnectionCount())
	}
}

func TestConnReadWriteClosed(t *testing.T) {
	// Create a UDP connection for testing
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to create UDP conn: %v", err)
	}

	remoteAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	conn := &Conn{
		underlying: udpConn,
		remoteAddr: remoteAddr,
	}

	conn.Close()

	// Read should fail on closed connection
	buf := make([]byte, 100)
	if _, err := conn.Read(buf); err != ErrTransportClosed {
		t.Errorf("Read() error = %v, want ErrTransportClosed", err)
	}

	// Write should fail on closed connection
	if _, err := conn.Write([]byte("test")); err != ErrTransportClosed {
		t.Errorf("Write() error = %v, want ErrTransportClosed", err)
	}
}

func TestConnAddresses(t *testing.T) {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to create UDP conn: %v", err)
	}
	defer udpConn.Close()

	remoteAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	conn := &Conn{
		underlying: udpConn,
		remoteAddr: remoteAddr,
	}

	if conn.RemoteAddr().String() != "127.0.0.1:12345" {
		t.Errorf("RemoteAddr = %s, want 127.0.0.1:12345", conn.RemoteAddr())
	}

	if conn.LocalAddr() == nil {
		t.Error("LocalAddr should not be nil")
	}
}
