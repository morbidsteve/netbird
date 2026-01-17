package fips

import (
	"crypto/tls"
	"testing"
)

func TestFIPSApprovedCipherSuites(t *testing.T) {
	suites := FIPSApprovedCipherSuites()

	if len(suites) == 0 {
		t.Fatal("expected at least one approved cipher suite")
	}

	// Verify AES-256-GCM is included (primary suite)
	found256 := false
	for _, s := range suites {
		if s == tls.TLS_AES_256_GCM_SHA384 {
			found256 = true
			break
		}
	}
	if !found256 {
		t.Error("TLS_AES_256_GCM_SHA384 should be in approved list")
	}

	// Verify AES-128-GCM is included (secondary suite)
	found128 := false
	for _, s := range suites {
		if s == tls.TLS_AES_128_GCM_SHA256 {
			found128 = true
			break
		}
	}
	if !found128 {
		t.Error("TLS_AES_128_GCM_SHA256 should be in approved list")
	}
}

func TestFIPSApprovedCurves(t *testing.T) {
	curves := FIPSApprovedCurves()

	if len(curves) == 0 {
		t.Fatal("expected at least one approved curve")
	}

	// Verify P-384 is first (preferred)
	if curves[0] != tls.CurveP384 {
		t.Error("P-384 should be the first (preferred) curve")
	}

	// Verify P-256 is included
	foundP256 := false
	for _, c := range curves {
		if c == tls.CurveP256 {
			foundP256 = true
			break
		}
	}
	if !foundP256 {
		t.Error("P-256 should be in approved curves list")
	}
}

func TestNewTLSConfig(t *testing.T) {
	cfg := NewTLSConfig()

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 minimum, got %d", cfg.MinVersion)
	}

	if cfg.MaxVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 maximum, got %d", cfg.MaxVersion)
	}

	if len(cfg.CurvePreferences) == 0 {
		t.Error("expected curve preferences to be set")
	}

	if len(cfg.CipherSuites) == 0 {
		t.Error("expected cipher suites to be set")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("FIPS should be disabled by default")
	}

	if cfg.Mode != ModeNative {
		t.Errorf("default mode should be native, got %s", cfg.Mode)
	}

	if !cfg.Strict {
		t.Error("strict mode should be true by default")
	}

	if cfg.MinTLSVersion != "1.3" {
		t.Errorf("default min TLS version should be 1.3, got %s", cfg.MinTLSVersion)
	}
}

func TestIsCipherSuiteApproved(t *testing.T) {
	tests := []struct {
		name     string
		suite    uint16
		approved bool
	}{
		{"AES-256-GCM-SHA384", tls.TLS_AES_256_GCM_SHA384, true},
		{"AES-128-GCM-SHA256", tls.TLS_AES_128_GCM_SHA256, true},
		{"ChaCha20-Poly1305", tls.TLS_CHACHA20_POLY1305_SHA256, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCipherSuiteApproved(tt.suite)
			if result != tt.approved {
				t.Errorf("IsCipherSuiteApproved(%d) = %v, want %v", tt.suite, result, tt.approved)
			}
		})
	}
}

func TestIsCurveApproved(t *testing.T) {
	tests := []struct {
		name     string
		curve    tls.CurveID
		approved bool
	}{
		{"P-384", tls.CurveP384, true},
		{"P-256", tls.CurveP256, true},
		{"X25519", tls.X25519, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCurveApproved(tt.curve)
			if result != tt.approved {
				t.Errorf("IsCurveApproved(%d) = %v, want %v", tt.curve, result, tt.approved)
			}
		})
	}
}

func TestValidateTLSConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		err := ValidateTLSConfig(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("valid FIPS config", func(t *testing.T) {
		cfg := NewTLSConfig()
		err := ValidateTLSConfig(cfg)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("TLS 1.0 rejected", func(t *testing.T) {
		cfg := &tls.Config{MinVersion: tls.VersionTLS10}
		err := ValidateTLSConfig(cfg)
		if err == nil {
			t.Error("expected error for TLS 1.0")
		}
	})
}

func TestGetStatus(t *testing.T) {
	status := GetStatus()

	// Mode should be native (since we're not building with openssl_fips tag)
	if status.Mode != ModeNative {
		t.Errorf("expected native mode, got %s", status.Mode)
	}

	// Module version should be set
	if status.ModuleVersion == "" {
		t.Error("module version should not be empty")
	}
}

func TestEnabled(t *testing.T) {
	// Just verify it doesn't panic and returns a boolean
	result := Enabled()
	t.Logf("FIPS enabled: %v", result)
}
