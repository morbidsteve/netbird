//go:build fips

package openssl

import (
	"testing"
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
