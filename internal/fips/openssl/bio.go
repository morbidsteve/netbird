//go:build fips

package openssl

/*
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>

// Custom BIO for Go net.Conn integration
// This uses memory BIOs and requires Go to shuttle data

typedef struct {
    BIO *rbio;  // Read BIO (data from network -> OpenSSL)
    BIO *wbio;  // Write BIO (data from OpenSSL -> network)
} bio_pair_t;

static bio_pair_t* create_bio_pair() {
    bio_pair_t *pair = (bio_pair_t *)malloc(sizeof(bio_pair_t));
    if (pair == NULL) return NULL;

    pair->rbio = BIO_new(BIO_s_mem());
    pair->wbio = BIO_new(BIO_s_mem());

    if (pair->rbio == NULL || pair->wbio == NULL) {
        if (pair->rbio) BIO_free(pair->rbio);
        if (pair->wbio) BIO_free(pair->wbio);
        free(pair);
        return NULL;
    }

    // Set BIOs to non-blocking
    BIO_set_nbio(pair->rbio, 1);
    BIO_set_nbio(pair->wbio, 1);

    return pair;
}

static void attach_bios(SSL *ssl, bio_pair_t *pair) {
    // SSL_set_bio takes ownership of the BIOs
    SSL_set_bio(ssl, pair->rbio, pair->wbio);
}

// Write data into the read BIO (simulates receiving from network)
static int bio_write_to_rbio(bio_pair_t *pair, const unsigned char *data, int len) {
    return BIO_write(pair->rbio, data, len);
}

// Read data from the write BIO (data to send to network)
static int bio_read_from_wbio(bio_pair_t *pair, unsigned char *data, int len) {
    return BIO_read(pair->wbio, data, len);
}

// Check if write BIO has pending data
static int bio_wbio_pending(bio_pair_t *pair) {
    return BIO_ctrl_pending(pair->wbio);
}
*/
import "C"

import (
	"unsafe"
)

// bioPair wraps OpenSSL memory BIOs for net.Conn integration.
type bioPair struct {
	pair *C.bio_pair_t
}

// newBIOPair creates a new BIO pair for shuttling data.
func newBIOPair() (*bioPair, error) {
	pair := C.create_bio_pair()
	if pair == nil {
		return nil, ErrNotInitialized
	}
	return &bioPair{pair: pair}, nil
}

// attachToSSL attaches this BIO pair to an SSL connection.
// Note: SSL_set_bio takes ownership of the BIOs, so we don't free them separately.
func (b *bioPair) attachToSSL(ssl *C.SSL) {
	C.attach_bios(ssl, b.pair)
}

// writeToRead writes data into the read BIO (simulating network receive).
func (b *bioPair) writeToRead(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	return int(C.bio_write_to_rbio(b.pair, (*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data))))
}

// readFromWrite reads data from the write BIO (data to send to network).
func (b *bioPair) readFromWrite(buf []byte) int {
	if len(buf) == 0 {
		return 0
	}
	return int(C.bio_read_from_wbio(b.pair, (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf))))
}

// pendingWrite returns the number of bytes pending in the write BIO.
func (b *bioPair) pendingWrite() int {
	return int(C.bio_wbio_pending(b.pair))
}
