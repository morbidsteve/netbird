package cmd

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/internal/fips"
)

var (
	fipsEnabled bool
	fipsStrict  bool
)

// fipsCmd represents the fips command for checking FIPS status
var fipsCmd = &cobra.Command{
	Use:   "fips",
	Short: "Display FIPS 140-3 compliance status",
	Long: `Display information about FIPS 140-3 compliance mode.

FIPS mode enables encryption using only FIPS 140-3 approved algorithms
for handling Controlled Unclassified Information (CUI).

When FIPS mode is enabled:
- Peer connections are wrapped with DTLS 1.3 using AES-256-GCM
- TLS connections use only FIPS-approved cipher suites
- Key exchange uses ECDHE with P-384 curves

To enable FIPS mode, set the environment variable:
  export GODEBUG=fips140=on
  export NETBIRD_FIPS_ENABLED=true`,
	RunE: fipsStatus,
}

func init() {
	rootCmd.AddCommand(fipsCmd)

	// Add FIPS flags to root command
	rootCmd.PersistentFlags().BoolVar(&fipsEnabled, "fips", false, "Enable FIPS 140-3 compliant mode")
	rootCmd.PersistentFlags().BoolVar(&fipsStrict, "fips-strict", true, "Fail if FIPS mode is requested but not available")
}

// fipsStatus displays the current FIPS compliance status
func fipsStatus(cmd *cobra.Command, args []string) error {
	status := fips.GetStatus()

	fmt.Println("FIPS 140-3 Compliance Status")
	fmt.Println("============================")
	fmt.Printf("FIPS Mode Enabled: %t\n", status.Enabled)
	fmt.Printf("Module Type:       %s\n", status.Mode)
	fmt.Printf("Module Version:    %s\n", status.ModuleVersion)
	fmt.Printf("CMVP Certificate:  %s\n", status.Certificate)
	fmt.Println()

	if status.Enabled {
		fmt.Println("FIPS-Approved Algorithms in Use:")
		fmt.Println("  - Key Exchange:  ECDHE P-384 (SP 800-56A)")
		fmt.Println("  - Encryption:    AES-256-GCM (FIPS 197, SP 800-38D)")
		fmt.Println("  - Signatures:    ECDSA P-384 (FIPS 186-5)")
		fmt.Println("  - Hashing:       SHA-384 (FIPS 180-4)")
	} else {
		fmt.Println("To enable FIPS mode:")
		fmt.Println("  1. Set environment: export GODEBUG=fips140=on")
		fmt.Println("  2. Run with --fips flag: netbird up --fips")
	}

	return nil
}

// InitFIPS initializes FIPS mode based on flags and environment.
// This should be called early in the application startup.
func InitFIPS() error {
	// Check environment variable override
	if os.Getenv("NETBIRD_FIPS_ENABLED") == "true" {
		fipsEnabled = true
	}

	cfg := fips.Config{
		Enabled: fipsEnabled,
		Mode:    fips.ModeNative,
		Strict:  fipsStrict,
	}

	if err := fips.Initialize(cfg); err != nil {
		return fmt.Errorf("FIPS initialization failed: %w", err)
	}

	if fipsEnabled {
		status := fips.GetStatus()
		if status.Enabled {
			log.Infof("FIPS 140-3 mode: enabled (%s)", status.Mode)
		} else {
			log.Warnf("FIPS mode requested but not active (GODEBUG=fips140=on required)")
		}
	}

	return nil
}

// MustInitFIPS is like InitFIPS but exits on error.
func MustInitFIPS() {
	if err := InitFIPS(); err != nil {
		log.Fatalf("FIPS initialization failed: %v", err)
	}
}

// IsFIPSEnabled returns whether FIPS mode is enabled.
func IsFIPSEnabled() bool {
	return fips.Enabled()
}
