//go:build fips

package openssl

/*
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>

// PSK callback data
typedef struct {
    unsigned char *psk;
    size_t psk_len;
    unsigned char *identity;
    size_t identity_len;
} psk_data_t;

// Client PSK callback
static unsigned int psk_client_cb(SSL *ssl, const char *hint,
    char *identity, unsigned int max_identity_len,
    unsigned char *psk, unsigned int max_psk_len) {

    psk_data_t *data = (psk_data_t *)SSL_get_app_data(ssl);
    if (data == NULL) return 0;

    if (data->identity_len >= max_identity_len) return 0;
    if (data->psk_len > max_psk_len) return 0;

    memcpy(identity, data->identity, data->identity_len);
    identity[data->identity_len] = '\0';
    memcpy(psk, data->psk, data->psk_len);

    return data->psk_len;
}

// Server PSK callback
static unsigned int psk_server_cb(SSL *ssl, const char *identity,
    unsigned char *psk, unsigned int max_psk_len) {

    psk_data_t *data = (psk_data_t *)SSL_get_app_data(ssl);
    if (data == NULL) return 0;

    if (data->psk_len > max_psk_len) return 0;
    memcpy(psk, data->psk, data->psk_len);

    return data->psk_len;
}

static SSL_CTX* create_dtls_ctx(int is_server) {
    const SSL_METHOD *method;
    if (is_server) {
        method = DTLS_server_method();
    } else {
        method = DTLS_client_method();
    }

    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) return NULL;

    // Set FIPS-approved cipher suites: PSK with AES-GCM
    if (!SSL_CTX_set_cipher_list(ctx, "PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256")) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set minimum version to DTLS 1.2
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);

    // Set PSK callbacks
    if (is_server) {
        SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);
    } else {
        SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
    }

    return ctx;
}

static psk_data_t* create_psk_data(unsigned char *psk, size_t psk_len,
    unsigned char *identity, size_t identity_len) {

    psk_data_t *data = (psk_data_t *)malloc(sizeof(psk_data_t));
    if (data == NULL) return NULL;

    data->psk = (unsigned char *)malloc(psk_len);
    if (data->psk == NULL) {
        free(data);
        return NULL;
    }
    memcpy(data->psk, psk, psk_len);
    data->psk_len = psk_len;

    data->identity = (unsigned char *)malloc(identity_len + 1);
    if (data->identity == NULL) {
        free(data->psk);
        free(data);
        return NULL;
    }
    memcpy(data->identity, identity, identity_len);
    data->identity[identity_len] = '\0';
    data->identity_len = identity_len;

    return data;
}

static void free_psk_data(psk_data_t *data) {
    if (data != NULL) {
        if (data->psk != NULL) {
            OPENSSL_cleanse(data->psk, data->psk_len);
            free(data->psk);
        }
        if (data->identity != NULL) {
            free(data->identity);
        }
        free(data);
    }
}

static const char* get_ssl_error_string(SSL *ssl, int ret) {
    int err = SSL_get_error(ssl, ret);
    switch (err) {
        case SSL_ERROR_NONE: return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL: return ERR_reason_error_string(ERR_get_error());
        case SSL_ERROR_WANT_READ: return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE: return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL: return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN: return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT: return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT: return "SSL_ERROR_WANT_ACCEPT";
        default: return "unknown SSL error";
    }
}

// Wrapper functions for OpenSSL macros (cgo can't call macros directly)
static void ssl_set_app_data_wrapper(SSL *ssl, void *data) {
    SSL_set_app_data(ssl, data);
}

static void ssl_set_mtu_wrapper(SSL *ssl, long mtu) {
    SSL_set_mtu(ssl, mtu);
}
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"
)

// DTLSConn wraps a net.Conn with DTLS encryption using OpenSSL.
type DTLSConn struct {
	mu       sync.Mutex
	conn     net.Conn
	ssl      *C.SSL
	ctx      *C.SSL_CTX
	bio      *bioPair
	pskData  *C.psk_data_t
	closed   bool
	isServer bool
}

// NewDTLSConn creates a new DTLS connection wrapping the provided net.Conn.
func NewDTLSConn(conn net.Conn, config *DTLSConfig) (*DTLSConn, error) {
	if !IsFIPSEnabled() {
		if err := InitFIPS(); err != nil {
			return nil, fmt.Errorf("FIPS init failed: %w", err)
		}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	isServer := 0
	if config.IsServer {
		isServer = 1
	}

	ctx := C.create_dtls_ctx(C.int(isServer))
	if ctx == nil {
		return nil, fmt.Errorf("failed to create DTLS context: %s", getOpenSSLError())
	}

	ssl := C.SSL_new(ctx)
	if ssl == nil {
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("failed to create SSL: %s", getOpenSSLError())
	}

	// Create BIO pair
	bio, err := newBIOPair()
	if err != nil {
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("failed to create BIO pair: %w", err)
	}
	bio.attachToSSL(ssl)

	// Set up PSK data
	pskData := C.create_psk_data(
		(*C.uchar)(unsafe.Pointer(&config.PSK[0])),
		C.size_t(len(config.PSK)),
		(*C.uchar)(unsafe.Pointer(&config.PSKIdentity[0])),
		C.size_t(len(config.PSKIdentity)),
	)
	if pskData == nil {
		C.SSL_free(ssl)
		C.SSL_CTX_free(ctx)
		return nil, fmt.Errorf("failed to create PSK data")
	}

	C.ssl_set_app_data_wrapper(ssl, unsafe.Pointer(pskData))

	// Set MTU if specified
	if config.MTU > 0 {
		C.ssl_set_mtu_wrapper(ssl, C.long(config.MTU))
	}

	return &DTLSConn{
		conn:     conn,
		ssl:      ssl,
		ctx:      ctx,
		bio:      bio,
		pskData:  pskData,
		isServer: config.IsServer,
	}, nil
}

// Handshake performs the DTLS handshake.
func (d *DTLSConn) Handshake(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrConnectionClosed
	}

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		d.conn.SetDeadline(deadline)
		defer d.conn.SetDeadline(time.Time{})
	}

	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var ret C.int
		if d.isServer {
			ret = C.SSL_accept(d.ssl)
		} else {
			ret = C.SSL_connect(d.ssl)
		}

		if ret == 1 {
			// Handshake complete
			return nil
		}

		err := C.SSL_get_error(d.ssl, ret)
		switch err {
		case C.SSL_ERROR_WANT_READ:
			// Send any pending data first
			if flushErr := d.flushWriteLocked(buf); flushErr != nil {
				return flushErr
			}
			// Read from network into BIO
			if readErr := d.readFromNetworkLocked(buf); readErr != nil {
				return readErr
			}

		case C.SSL_ERROR_WANT_WRITE:
			if flushErr := d.flushWriteLocked(buf); flushErr != nil {
				return flushErr
			}

		default:
			errStr := C.GoString(C.get_ssl_error_string(d.ssl, ret))
			return fmt.Errorf("%w: %s", ErrHandshakeFailed, errStr)
		}
	}
}

func (d *DTLSConn) flushWriteLocked(buf []byte) error {
	for d.bio.pendingWrite() > 0 {
		n := d.bio.readFromWrite(buf)
		if n > 0 {
			if _, err := d.conn.Write(buf[:n]); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *DTLSConn) readFromNetworkLocked(buf []byte) error {
	n, err := d.conn.Read(buf)
	if err != nil {
		return err
	}
	if n > 0 {
		d.bio.writeToRead(buf[:n])
	}
	return nil
}

// Read reads data from the DTLS connection.
func (d *DTLSConn) Read(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return 0, ErrConnectionClosed
	}

	buf := make([]byte, 4096)

	for {
		// Try to read from SSL first
		ret := C.SSL_read(d.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
		if ret > 0 {
			return int(ret), nil
		}

		err := C.SSL_get_error(d.ssl, ret)
		if err == C.SSL_ERROR_WANT_READ {
			// Need more data from network
			if readErr := d.readFromNetworkLocked(buf); readErr != nil {
				return 0, readErr
			}
			continue
		}

		if err == C.SSL_ERROR_ZERO_RETURN {
			return 0, ErrConnectionClosed
		}

		return 0, fmt.Errorf("SSL_read error: %s", C.GoString(C.get_ssl_error_string(d.ssl, ret)))
	}
}

// Write writes data to the DTLS connection.
func (d *DTLSConn) Write(b []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return 0, ErrConnectionClosed
	}

	ret := C.SSL_write(d.ssl, unsafe.Pointer(&b[0]), C.int(len(b)))
	if ret <= 0 {
		return 0, fmt.Errorf("SSL_write error: %s", C.GoString(C.get_ssl_error_string(d.ssl, ret)))
	}

	// Flush to network
	buf := make([]byte, 4096)
	if err := d.flushWriteLocked(buf); err != nil {
		return 0, err
	}

	return int(ret), nil
}

// Close closes the DTLS connection.
func (d *DTLSConn) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true

	if d.ssl != nil {
		C.SSL_shutdown(d.ssl)
		C.SSL_free(d.ssl) // This also frees the attached BIOs
		d.ssl = nil
	}

	if d.ctx != nil {
		C.SSL_CTX_free(d.ctx)
		d.ctx = nil
	}

	if d.pskData != nil {
		C.free_psk_data(d.pskData)
		d.pskData = nil
	}

	return d.conn.Close()
}

// LocalAddr returns the local network address.
func (d *DTLSConn) LocalAddr() net.Addr {
	return d.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (d *DTLSConn) RemoteAddr() net.Addr {
	return d.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (d *DTLSConn) SetDeadline(t time.Time) error {
	return d.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (d *DTLSConn) SetReadDeadline(t time.Time) error {
	return d.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (d *DTLSConn) SetWriteDeadline(t time.Time) error {
	return d.conn.SetWriteDeadline(t)
}

// CipherSuite returns the negotiated cipher suite name.
func (d *DTLSConn) CipherSuite() string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.ssl == nil {
		return ""
	}

	cipher := C.SSL_get_current_cipher(d.ssl)
	if cipher == nil {
		return ""
	}

	return C.GoString(C.SSL_CIPHER_get_name(cipher))
}

func getOpenSSLError() string {
	errCode := C.ERR_get_error()
	if errCode == 0 {
		return "no error"
	}
	return C.GoString(C.ERR_reason_error_string(errCode))
}
