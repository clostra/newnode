#ifndef __OBFOO_H__
#define __OBFOO_H__

#include <sodium.h>

#include "log.h"
#include "network.h"


/*
q = crypto_scalarmult(q, my_sk, their_pk)
rx,tx = h(q ‖ client_publickey ‖ server_publickey)

ENCRYPT() is ChaCha20, that uses the following keys to send data:
rx,tx

1 A->B: crypto_kx_PUBLICKEYBYTES, crypto_stream_chacha20_NONCEBYTES, PadA
2 B->A: crypto_kx_PUBLICKEYBYTES, crypto_stream_chacha20_NONCEBYTES, PadB
3 A->B: HASH('req1', tx), ENCRYPT(VC, crypto_provide, len(PadC), PadC)
4 B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
5 A->B: ENCRYPT2(Payload Stream)
*/


#define crypto_stream_chacha20_BLOCK_LENGTH 64

#define INTRO_BYTES (crypto_kx_PUBLICKEYBYTES + crypto_stream_chacha20_NONCEBYTES)
static_assert(crypto_stream_chacha20_KEYBYTES <= crypto_kx_SESSIONKEYBYTES, "chacha20 is used as session key");

#define PAD_MAX 256
#define INTRO_PAD_MAX ((96 + PAD_MAX) - INTRO_BYTES)

// 2*sizeof(blake2b)
#define SYNC_HASH_LEN 40
static_assert(SYNC_HASH_LEN >= crypto_generichash_blake2b_BYTES_MIN, "sync hash must fit in blake2b size");
static_assert(SYNC_HASH_LEN <= crypto_generichash_blake2b_BYTES_MAX, "sync hash must fit in blake2b size");

typedef struct {
    uint64_t vc;
    uint32_t crypto_provide;
    uint16_t pad_len;
    uint8_t pad[];
} PACKED crypt_intro;

typedef enum {
    OF_STATE_INTRO = 0,
    OF_STATE_SYNC,
    OF_STATE_DISCARD,
    OF_STATE_READY
} of_state;

typedef struct {
    uint8_t pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t sk[crypto_kx_SECRETKEYBYTES];
    uint8_t rx[crypto_kx_SESSIONKEYBYTES];
    uint8_t tx[crypto_kx_SESSIONKEYBYTES];
    uint8_t rx_nonce[crypto_stream_chacha20_NONCEBYTES];
    uint8_t tx_nonce[crypto_stream_chacha20_NONCEBYTES];
    uint64_t rx_ic_bytes;
    uint64_t tx_ic_bytes;
    union {
        // incoming
        uint8_t synchash[SYNC_HASH_LEN];
        // outgoing
        uint8_t vc[member_sizeof(crypt_intro, vc)];
    };
    of_state state;
    evbuffer *output;
    uint16_t discarding;
    bool incoming:1;
} obfoo;

obfoo* obfoo_new(void);
void obfoo_write_intro(obfoo *o, evbuffer *out);
ssize_t obfoo_input_filter(evbuffer *in, evbuffer *out, obfoo *o);
ssize_t obfoo_output_filter(evbuffer *in, evbuffer *out, obfoo *o);
void obfoo_free(obfoo *o);

#endif // __OBFOO_H__
