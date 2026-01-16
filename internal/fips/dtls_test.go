package fips

import (
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

func TestFIPSApprovedDTLSCipherSuites(t *testing.T) {
	suites := FIPSApprovedDTLSCipherSuites()

	if len(suites) == 0 {
		t.Fatal("expected at least one FIPS cipher suite")
	}

	// Verify preferred cipher is first
	if suites[0] != DTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
		t.Error("ECDHE-ECDSA-AES256-GCM should be first (preferred)")
	}

	// Verify all suites are AES-GCM based
	for _, suite := range suites {
		// All approved suites should have GCM in their identifier range
		if suite < 0xc02b || suite > 0xc030 {
			t.Errorf("unexpected cipher suite: 0x%04x", suite)
		}
	}
}

func TestIsDTLSCipherSuiteApproved(t *testing.T) {
	tests := []struct {
		name     string
		suite    DTLSCipherSuite
		approved bool
	}{
		{
			name:     "ECDHE-ECDSA-AES256-GCM-SHA384",
			suite:    DTLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			approved: true,
		},
		{
			name:     "ECDHE-RSA-AES256-GCM-SHA384",
			suite:    DTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			approved: true,
		},
		{
			name:     "ECDHE-ECDSA-AES128-GCM-SHA256",
			suite:    DTLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			approved: true,
		},
		{
			name:     "Non-FIPS suite",
			suite:    DTLSCipherSuite(0x0000),
			approved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsDTLSCipherSuiteApproved(tt.suite)
			if result != tt.approved {
				t.Errorf("IsDTLSCipherSuiteApproved(0x%04x) = %v, want %v",
					tt.suite, result, tt.approved)
			}
		})
	}
}

func TestDefaultDTLSConfig(t *testing.T) {
	cfg := DefaultDTLSConfig()

	if cfg.MTU <= 0 {
		t.Error("MTU should be positive")
	}
	if cfg.MTU > 1500 {
		t.Error("MTU should not exceed ethernet MTU")
	}
	if cfg.MTU != 1350 {
		t.Errorf("default MTU should be 1350, got %d", cfg.MTU)
	}

	if cfg.SessionTimeout <= 0 {
		t.Error("session timeout should be positive")
	}
	if cfg.HandshakeTimeout <= 0 {
		t.Error("handshake timeout should be positive")
	}
}

func TestValidateDTLSConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     DTLSConfig
		wantErr bool
	}{
		{
			name:    "valid default config",
			cfg:     DefaultDTLSConfig(),
			wantErr: false,
		},
		{
			name: "MTU too low",
			cfg: DTLSConfig{
				MTU:              100,
				SessionTimeout:   time.Hour,
				HandshakeTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "MTU too high",
			cfg: DTLSConfig{
				MTU:              9000,
				SessionTimeout:   time.Hour,
				HandshakeTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "session timeout too short",
			cfg: DTLSConfig{
				MTU:              1350,
				SessionTimeout:   time.Second,
				HandshakeTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "handshake timeout too short",
			cfg: DTLSConfig{
				MTU:              1350,
				SessionTimeout:   time.Hour,
				HandshakeTimeout: time.Millisecond,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDTLSConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDTLSConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

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

func TestNewDTLSClientTLSConfig(t *testing.T) {
	cert, pool, err := generateTestCertP384()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	opts := DTLSClientConfigOptions{
		ServerName: "test.local",
		RootCAs:    pool,
		ClientCert: cert,
		Config:     DefaultDTLSConfig(),
	}

	cfg := NewDTLSClientTLSConfig(opts)

	if cfg.ServerName != "test.local" {
		t.Errorf("ServerName = %s, want test.local", cfg.ServerName)
	}

	if cfg.MinVersion != tls.VersionTLS12 {
		t.Error("MinVersion should be TLS 1.2 for DTLS")
	}

	if len(cfg.Certificates) == 0 {
		t.Error("client certificate should be set")
	}

	if len(cfg.CipherSuites) == 0 {
		t.Error("cipher suites should be set")
	}

	// Verify only FIPS cipher suites
	for _, suite := range cfg.CipherSuites {
		if !IsDTLSCipherSuiteApproved(DTLSCipherSuite(suite)) {
			t.Errorf("non-FIPS cipher suite in config: 0x%04x", suite)
		}
	}
}

func TestNewDTLSServerTLSConfig(t *testing.T) {
	cert, pool, err := generateTestCertP384()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	opts := DTLSServerConfigOptions{
		Certificate:       cert,
		ClientCAs:         pool,
		RequireClientCert: true,
		Config:            DefaultDTLSConfig(),
	}

	cfg := NewDTLSServerTLSConfig(opts)

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("ClientAuth should require client cert")
	}

	if len(cfg.Certificates) == 0 {
		t.Error("server certificate should be set")
	}

	if cfg.ClientCAs == nil {
		t.Error("ClientCAs should be set")
	}
}

func TestFIPSApprovedDTLSCipherSuitesUint16(t *testing.T) {
	suites := FIPSApprovedDTLSCipherSuitesUint16()

	if len(suites) == 0 {
		t.Fatal("expected at least one cipher suite")
	}

	// Verify conversion is correct
	originalSuites := FIPSApprovedDTLSCipherSuites()
	if len(suites) != len(originalSuites) {
		t.Errorf("length mismatch: got %d, want %d", len(suites), len(originalSuites))
	}

	for i, suite := range suites {
		if suite != uint16(originalSuites[i]) {
			t.Errorf("suite[%d] = 0x%04x, want 0x%04x", i, suite, originalSuites[i])
		}
	}
}
