//go:build fips

package openssl

/*
#cgo CFLAGS: -I/opt/homebrew/opt/openssl@3/include -I/usr/local/opt/openssl@3/include -I/usr/include
#cgo LDFLAGS: -L/opt/homebrew/opt/openssl@3/lib -L/usr/local/opt/openssl@3/lib -L/usr/lib -lssl -lcrypto

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <stdlib.h>

static OSSL_PROVIDER *fips_provider = NULL;
static OSSL_PROVIDER *base_provider = NULL;

int init_fips_provider() {
    fips_provider = OSSL_PROVIDER_load(NULL, "fips");
    if (fips_provider == NULL) {
        return -1;
    }

    base_provider = OSSL_PROVIDER_load(NULL, "base");
    if (base_provider == NULL) {
        OSSL_PROVIDER_unload(fips_provider);
        return -2;
    }

    if (!EVP_set_default_properties(NULL, "fips=yes")) {
        return -3;
    }

    return 0;
}

int is_fips_enabled() {
    // Check if FIPS provider was loaded successfully
    return (fips_provider != NULL) ? 1 : 0;
}

void cleanup_providers() {
    if (fips_provider != NULL) {
        OSSL_PROVIDER_unload(fips_provider);
        fips_provider = NULL;
    }
    if (base_provider != NULL) {
        OSSL_PROVIDER_unload(base_provider);
        base_provider = NULL;
    }
}

const char* get_openssl_error() {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "no error";
    }
    return ERR_reason_error_string(err);
}

const char* get_openssl_version() {
    return OpenSSL_version(OPENSSL_VERSION);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"sync"
)

var (
	initOnce   sync.Once
	initErr    error
	fipsActive bool
)

// InitFIPS initializes the OpenSSL FIPS provider.
// This must be called before any cryptographic operations.
// It is safe to call multiple times; initialization only happens once.
func InitFIPS() error {
	initOnce.Do(func() {
		// OpenSSL 3.x auto-initializes; SSL_library_init and SSL_load_error_strings
		// are deprecated and not needed.

		ret := C.init_fips_provider()
		if ret != 0 {
			errStr := C.GoString(C.get_openssl_error())
			initErr = fmt.Errorf("failed to initialize FIPS provider (code %d): %s", ret, errStr)
			return
		}

		if C.is_fips_enabled() != 1 {
			initErr = errors.New("FIPS mode not active after initialization")
			return
		}

		fipsActive = true
	})
	return initErr
}

// IsFIPSEnabled returns true if FIPS mode is active.
func IsFIPSEnabled() bool {
	return fipsActive && C.is_fips_enabled() == 1
}

// Cleanup releases OpenSSL resources. Call on program exit.
func Cleanup() {
	C.cleanup_providers()
	fipsActive = false
}

// Version returns the OpenSSL version string.
func Version() string {
	return C.GoString(C.get_openssl_version())
}
