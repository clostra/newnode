#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>

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
3 A->B: HASH('req1', tx), ENCRYPT(VC, crypto_provide, len(PadC), PadC, len(IA)), ENCRYPT(IA)
4 B->A: ENCRYPT(VC, crypto_select, len(padD), padD), ENCRYPT2(Payload Stream)
5 A->B: ENCRYPT2(Payload Stream)
*/

#define xtkn(x, y) x ## y
#define tkn(x, y) xtkn(x, y)
#define COMPILER_ASSERT(X) struct tkn(__d_, __LINE__) { char b[sizeof(char[(X) ? 1 : -1])]; }

#define STREAM_BLOCK_LEN 64

#define INTRO_BYTES (crypto_kx_PUBLICKEYBYTES + crypto_stream_chacha20_NONCEBYTES)
COMPILER_ASSERT(crypto_stream_chacha20_KEYBYTES <= crypto_kx_SESSIONKEYBYTES);

#define PAD_MAX 256
#define INTRO_PAD_MAX ((96 + PAD_MAX) - INTRO_BYTES)

// 2*sizeof(sha1)
#define SYNC_HASH_LEN 40
COMPILER_ASSERT(SYNC_HASH_LEN >= crypto_generichash_blake2b_BYTES_MIN);
COMPILER_ASSERT(SYNC_HASH_LEN <= crypto_generichash_blake2b_BYTES_MAX);

typedef struct {
    uint64_t vc;
    uint32_t crypto_provide;
    uint16_t pad_len;
    uint8_t pad[];
} PACKED crypt_intro;

typedef enum {
    OF_STATE_DISABLED = -1,
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
    bufferevent *filter_bev;
    uint16_t discarding;
    bool incoming:1;
} obfoo;

int crypto_stream_chacha20_xor_ic_bytes(uint8_t *c, const uint8_t *m, size_t mlen,
                                        const unsigned char *n, uint64_t ic_bytes,
                                        const unsigned char *k)
{
    size_t partial = ic_bytes % STREAM_BLOCK_LEN;
    if (partial) {
        uint8_t block[STREAM_BLOCK_LEN] = {0};
        uint8_t *p = &block[partial];
        size_t plen = MIN(STREAM_BLOCK_LEN - partial, mlen);
        memcpy(p, m, plen);
        int r = crypto_stream_chacha20_xor_ic(block, block, &p[plen] - block, n, ic_bytes / STREAM_BLOCK_LEN, k);
        if (r != 0) {
            return r;
        }
        memcpy(c, p, plen);
        c += plen;
        m += plen;
        mlen -= plen;
        ic_bytes += plen;
    }
    return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic_bytes / STREAM_BLOCK_LEN, k);
}

int obfoo_encrypt(obfoo *o, uint8_t *c, const uint8_t *m, size_t mlen)
{
    int r = crypto_stream_chacha20_xor_ic_bytes(c, m, mlen, o->tx_nonce, o->tx_ic_bytes, o->tx);
    o->tx_ic_bytes += mlen;
    return r;
}

int obfoo_decrypt(obfoo *o, uint8_t *m, const uint8_t *c, size_t clen)
{
    int r = crypto_stream_chacha20_xor_ic_bytes(m, c, clen, o->rx_nonce, o->rx_ic_bytes, o->rx);
    o->rx_ic_bytes += clen;
    return r;
}

void obfoo_write_intro(obfoo *o, bufferevent *bev)
{
    bufferevent_disable(bev, EV_WRITE);
    bufferevent_write(bev, o->pk, sizeof(o->pk));
    bufferevent_write(bev, o->tx_nonce, sizeof(o->tx_nonce));
    uint16_t pad_len = randombytes_uniform(INTRO_PAD_MAX);
    uint8_t pad[pad_len];
    randombytes_buf(pad, sizeof(pad));
    bufferevent_write(bev, pad, sizeof(pad));
    bufferevent_enable(bev, EV_WRITE);
}

obfoo* obfoo_new()
{
    obfoo *o = alloc(obfoo);
    crypto_kx_keypair(o->pk, o->sk);
    randombytes_buf(o->tx_nonce, sizeof(o->tx_nonce));
    return o;
}

ssize_t evbuffer_filter(evbuffer *in, evbuffer *out, bool (^cb)(evbuffer_iovec v))
{
    evbuffer_ptr ptr;
    evbuffer_ptr_set(in, &ptr, 0, EVBUFFER_PTR_SET);
    evbuffer_iovec v;
    while (evbuffer_peek(in, -1, &ptr, &v, 1) > 0) {
        if (!cb(v)) {
            return -1;
        }
        if (evbuffer_ptr_set(in, &ptr, v.iov_len, EVBUFFER_PTR_ADD) < 0) {
            break;
        }
    }
    return evbuffer_remove_buffer(in, out, evbuffer_get_length(in));
}

bufferevent_filter_result obfoo_input_filter(evbuffer *in, evbuffer *out,
    ev_ssize_t dst_limit, bufferevent_flush_mode mode, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    //debug("%s: o:%p state:%d\n", __func__, o, o->state);
    switch(o->state) {
    case OF_STATE_DISABLED:
        return (evbuffer_remove_buffer(in, out, dst_limit) >= 0) ? BEV_OK : BEV_ERROR;
    case OF_STATE_INTRO: {

        // XXX: temporary plaintext support
        if (evbuffer_get_length(in) < 8) {
            return BEV_NEED_MORE;
        }
#define method_matches(s, m) strncaseeq((char*)s, m, lenof(m) - 1)
        uint8_t *start = evbuffer_pullup(in, 8);
        if (method_matches(start, "GET ") ||
            method_matches(start, "PUT ") ||
            method_matches(start, "POST ") ||
            method_matches(start, "HEAD ") ||
            method_matches(start, "TRACE ") ||
            method_matches(start, "PATCH ") ||
            method_matches(start, "DELETE ") ||
            method_matches(start, "OPTIONS ") ||
            method_matches(start, "CONNECT ")) {
            o->state = OF_STATE_DISABLED;
            return obfoo_input_filter(in, out, dst_limit, mode, ctx);
        }
#undef method_matches

        if (evbuffer_get_length(in) < INTRO_BYTES) {
            return BEV_NEED_MORE;
        }
        uint8_t *other_pk = evbuffer_pullup(in, crypto_kx_PUBLICKEYBYTES);

        if (o->incoming) {
            if (crypto_kx_server_session_keys(o->rx, o->tx, o->pk, o->sk, other_pk)) {
                debug("suspicious client public key\n");
                return BEV_ERROR;
            }
        } else {
            if (crypto_kx_client_session_keys(o->rx, o->tx, o->pk, o->sk, other_pk)) {
                debug("suspicious server public key\n");
                return BEV_ERROR;
            }
        }

        evbuffer_drain(in, crypto_kx_PUBLICKEYBYTES);
        evbuffer_remove(in, o->rx_nonce, sizeof(o->rx_nonce));

        crypto_generichash_state state;
        crypto_generichash_init(&state, NULL, 0, sizeof(SYNC_HASH_LEN));
        crypto_generichash_update(&state, (const uint8_t *)"req1", strlen("req1"));

        if (o->incoming) {
            crypto_generichash_update(&state, o->rx, sizeof(o->rx));
            crypto_generichash_final(&state, o->synchash, sizeof(o->synchash));

            obfoo_write_intro(o, bufferevent_get_underlying(o->filter_bev));
        } else {
            bufferevent_disable(bufferevent_get_underlying(o->filter_bev), EV_WRITE);

            uint8_t synchash[SYNC_HASH_LEN];
            crypto_generichash_update(&state, o->tx, sizeof(o->tx));
            crypto_generichash_final(&state, synchash, sizeof(synchash));
            bufferevent_write(bufferevent_get_underlying(o->filter_bev), synchash, sizeof(synchash));

            // vc,crypto_provide,(uint16_t)len(pad),pad,len(ia)
            union {
                uint8_t buf[sizeof(crypt_intro) + PAD_MAX + sizeof(uint16_t)];
                crypt_intro ci;
            } r = {.buf = {0}};
            r.ci.pad_len = randombytes_uniform(PAD_MAX);
            randombytes_buf(r.ci.pad, r.ci.pad_len);
            size_t crypt_len = sizeof(crypt_intro) + r.ci.pad_len + sizeof(uint16_t);
            obfoo_encrypt(o, r.buf, r.buf, crypt_len);
            bufferevent_write(bufferevent_get_underlying(o->filter_bev), r.buf, crypt_len);

            bufferevent_enable(bufferevent_get_underlying(o->filter_bev), EV_WRITE);

            // encrypt vc from the other side
            crypto_stream_chacha20_xor_ic(o->vc, o->vc, sizeof(o->vc), o->rx_nonce, 0, o->rx);
        }

        o->state = OF_STATE_SYNC;
    }
    case OF_STATE_SYNC: {
        size_t sync_len = (o->incoming ? sizeof(o->synchash) : 0) + sizeof(crypt_intro);
        uint8_t *search = o->incoming ? o->synchash : o->vc;
        size_t search_len = o->incoming ? sizeof(o->synchash) : sizeof(o->vc);
        if (evbuffer_get_length(in) < sync_len) {
            return BEV_NEED_MORE;
        }
        evbuffer_ptr f = evbuffer_search(in, (char*)search, search_len, NULL);
        if (f.pos == -1) {
            size_t max_len = INTRO_PAD_MAX + search_len;
            if (evbuffer_get_length(in) >= max_len) {
                debug("sync not found in %llu (%llu) bytes\n", max_len, evbuffer_get_length(in));
                return BEV_ERROR;
            }
            return BEV_NEED_MORE;
        }
        evbuffer_drain(in, f.pos);
        //debug("sync found!\n");

        if (o->incoming) {
            evbuffer_drain(in, sizeof(o->synchash));
        }

        crypt_intro *ci = (crypt_intro*)evbuffer_pullup(in, sizeof(crypt_intro));
        obfoo_decrypt(o, (uint8_t*)ci, (uint8_t*)ci, sizeof(crypt_intro));
        if (ci->vc != 0) {
            debug("incorrect vc: %llu != 0\n", ci->vc);
            return BEV_ERROR;
        }
        o->discarding = ci->pad_len;
        evbuffer_drain(in, sizeof(crypt_intro));

        if (o->incoming) {
            // len(ia)
            o->discarding += sizeof(uint16_t);

            // vc,crypto_select,(uint16_t)len(pad),pad
            union {
                uint8_t buf[sizeof(crypt_intro) + PAD_MAX];
                crypt_intro ci;
            } r = {.buf = {0}};
            r.ci.pad_len = randombytes_uniform(PAD_MAX);
            randombytes_buf(r.ci.pad, r.ci.pad_len);
            size_t crypt_len = sizeof(r.ci) + r.ci.pad_len;
            obfoo_encrypt(o, r.buf, r.buf, crypt_len);
            bufferevent_write(bufferevent_get_underlying(o->filter_bev), r.buf, crypt_len);
        }

        o->state = OF_STATE_DISCARD;
        // writing is now possible, flush
        bufferevent_flush(o->filter_bev, EV_WRITE, BEV_NORMAL);
    }
    case OF_STATE_DISCARD: {
        size_t discard = MIN(evbuffer_get_length(in), o->discarding);
        o->rx_ic_bytes += discard;
        evbuffer_drain(in, discard);
        o->discarding -= discard;
        if (o->discarding) {
            return BEV_NEED_MORE;
        }
        o->state = OF_STATE_READY;
    }
    case OF_STATE_READY: {
        ssize_t m = evbuffer_filter(in, out, ^bool (evbuffer_iovec v) {
            return !obfoo_decrypt(o, v.iov_base, v.iov_base, v.iov_len);
        });
        return m == -1 ? BEV_ERROR : (m > 0 ? BEV_OK : BEV_NEED_MORE);
    }
    }
}

bufferevent_filter_result obfoo_output_filter(evbuffer *in, evbuffer *out,
    ev_ssize_t dst_limit, bufferevent_flush_mode mode, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    //debug("%s: o:%p state:%d\n", __func__, o, o->state);
    switch(o->state) {
    case OF_STATE_DISABLED:
        return (evbuffer_remove_buffer(in, out, dst_limit) >= 0) ? BEV_OK : BEV_ERROR;
    default:
        return BEV_NEED_MORE;
    case OF_STATE_DISCARD:
    case OF_STATE_READY: {
        ssize_t m = evbuffer_filter(in, out, ^bool (evbuffer_iovec v) {
            return obfoo_encrypt(o, v.iov_base, v.iov_base, v.iov_len) == 0;
        });
        return m == -1 ? BEV_ERROR : (m > 0 ? BEV_OK : BEV_NEED_MORE);
    }
    }
}

void obfoo_free(void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    //debug("%s o:%p\n", __func__, o);
    free(o);
}

bufferevent* obfoo_filter(bufferevent *underlying, bool incoming)
{
    obfoo *o = obfoo_new();
    //debug("%s: o:%p incoming:%d\n", __func__, o, incoming);
    o->incoming = incoming;
    if (!o->incoming) {
        obfoo_write_intro(o, underlying);
    }
    bufferevent *bev = bufferevent_filter_new(underlying,
                   obfoo_input_filter, obfoo_output_filter,
                   BEV_OPT_CLOSE_ON_FREE, obfoo_free, o);
    o->filter_bev = bev;
    return bev;
}
