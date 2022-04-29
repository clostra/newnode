#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "obfoo.h"


int crypto_stream_chacha20_xor_ic_bytes(uint8_t *c, const uint8_t *m, size_t mlen,
                                        const unsigned char *n, uint64_t ic_bytes,
                                        const unsigned char *k)
{
    size_t partial = ic_bytes % crypto_stream_chacha20_BLOCK_LENGTH;
    if (partial) {
        uint8_t block[crypto_stream_chacha20_BLOCK_LENGTH] = {0};
        uint8_t *p = &block[partial];
        size_t plen = MIN(crypto_stream_chacha20_BLOCK_LENGTH - partial, mlen);
        memcpy(p, m, plen);
        int r = crypto_stream_chacha20_xor_ic(block, block, &p[plen] - block, n, ic_bytes / crypto_stream_chacha20_BLOCK_LENGTH, k);
        if (r != 0) {
            return r;
        }
        memcpy(c, p, plen);
        c += plen;
        m += plen;
        mlen -= plen;
        ic_bytes += plen;
    }
    return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic_bytes / crypto_stream_chacha20_BLOCK_LENGTH, k);
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

void obfoo_write_intro(obfoo *o, evbuffer *out)
{
    evbuffer_auto_free evbuffer *buf = evbuffer_new();
    evbuffer_add(buf, o->pk, sizeof(o->pk));
    evbuffer_add(buf, o->tx_nonce, sizeof(o->tx_nonce));
    uint16_t pad_len = (uint16_t)randombytes_uniform(INTRO_PAD_MAX);
    uint8_t pad[pad_len];
    randombytes_buf(pad, sizeof(pad));
    evbuffer_add(buf, pad, sizeof(pad));
    evbuffer_add_buffer(out, buf);
}

obfoo* obfoo_new()
{
    obfoo *o = alloc(obfoo);
    crypto_kx_keypair(o->pk, o->sk);
    randombytes_buf(o->tx_nonce, sizeof(o->tx_nonce));
    return o;
}

void obfoo_free(obfoo *o)
{
    free(o);
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
    ssize_t len = evbuffer_get_length(in);
    if (evbuffer_add_buffer(out, in) < 0) {
        return -1;
    }
    return len;
}

ssize_t obfoo_input_filter(obfoo *o, evbuffer *in, evbuffer *out, evbuffer *response)
{
    //debug("%s: o:%p state:%d incoming:%d\n", __func__, o, o->state, o->incoming);
    switch(o->state) {
    case OF_STATE_INTRO: {

        if (evbuffer_get_length(in) < INTRO_BYTES) {
            return 0;
        }
        uint8_t *other_pk = evbuffer_pullup(in, crypto_kx_PUBLICKEYBYTES);

        if (o->incoming) {
            if (crypto_kx_server_session_keys(o->rx, o->tx, o->pk, o->sk, other_pk)) {
                debug("suspicious client public key\n");
                return -1;
            }
        } else {
            if (crypto_kx_client_session_keys(o->rx, o->tx, o->pk, o->sk, other_pk)) {
                debug("suspicious server public key\n");
                return -1;
            }
        }
        // session keys are generated, destroy secret key
        memset(o->sk, 0, sizeof(o->sk));

        evbuffer_drain(in, crypto_kx_PUBLICKEYBYTES);
        evbuffer_remove(in, o->rx_nonce, sizeof(o->rx_nonce));

        crypto_generichash_state state;
        crypto_generichash_init(&state, NULL, 0, sizeof(SYNC_HASH_LEN));
        crypto_generichash_update(&state, (const uint8_t *)"req1", strlen("req1"));

        if (o->incoming) {
            crypto_generichash_update(&state, o->rx, sizeof(o->rx));
            crypto_generichash_final(&state, o->synchash, sizeof(o->synchash));

            obfoo_write_intro(o, response);
        } else {
            evbuffer_auto_free evbuffer *buf = evbuffer_new();

            uint8_t synchash[SYNC_HASH_LEN];
            crypto_generichash_update(&state, o->tx, sizeof(o->tx));
            crypto_generichash_final(&state, synchash, sizeof(synchash));
            evbuffer_add(buf, synchash, sizeof(synchash));

            // vc,crypto_provide,(uint16_t)len(pad),pad,len(ia)
            union {
                uint8_t buf[sizeof(crypt_intro) + PAD_MAX + sizeof(uint16_t)];
                crypt_intro ci;
            } r = {.buf = {0}};
            r.ci.crypto_provide = 0x01;
            r.ci.pad_len = (uint16_t)randombytes_uniform(PAD_MAX);
            randombytes_buf(r.ci.pad, r.ci.pad_len);
            size_t crypt_len = sizeof(crypt_intro) + r.ci.pad_len + sizeof(uint16_t);
            obfoo_encrypt(o, r.buf, r.buf, crypt_len);
            evbuffer_add(buf, r.buf, crypt_len);

            evbuffer_add_buffer(response, buf);

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
            return 0;
        }
        evbuffer_ptr f = evbuffer_search(in, (char*)search, search_len, NULL);
        if (f.pos == -1) {
            size_t max_len = INTRO_PAD_MAX + search_len;
            if (evbuffer_get_length(in) >= max_len) {
                debug("sync not found in %zu (%zu) bytes\n", max_len, evbuffer_get_length(in));
                return -1;
            }
            return 0;
        }
        evbuffer_drain(in, f.pos);
        //debug("sync found!\n");

        if (o->incoming) {
            evbuffer_drain(in, sizeof(o->synchash));
        }

        crypt_intro *ci = (crypt_intro*)evbuffer_pullup(in, sizeof(crypt_intro));
        obfoo_decrypt(o, (uint8_t*)ci, (uint8_t*)ci, sizeof(crypt_intro));
        if (ci->vc != 0) {
            debug("incorrect vc: %llu != 0\n", (unsigned long long)ci->vc);
            return -1;
        }
        if (ci->crypto_provide > 0x01) {
            debug("unsupported crypto_provide: %u > 0x01\n", ci->crypto_provide);
            return -1;
        }
        o->discarding = ci->pad_len;
        evbuffer_drain(in, sizeof(crypt_intro));

        if (o->incoming) {
            // len(ia)
            o->discarding += sizeof(uint16_t);

            // vc,crypto_provide,(uint16_t)len(pad),pad
            union {
                uint8_t buf[sizeof(crypt_intro) + PAD_MAX];
                crypt_intro ci;
            } r = {.buf = {0}};
            r.ci.crypto_provide = 0x01;
            r.ci.pad_len = (uint16_t)randombytes_uniform(PAD_MAX);
            randombytes_buf(r.ci.pad, r.ci.pad_len);
            size_t crypt_len = sizeof(r.ci) + r.ci.pad_len;
            obfoo_encrypt(o, r.buf, r.buf, crypt_len);
            evbuffer_add(response, r.buf, crypt_len);
        }

        o->state = OF_STATE_DISCARD;
    }
    case OF_STATE_DISCARD: {
        size_t discard = MIN(evbuffer_get_length(in), o->discarding);
        o->rx_ic_bytes += discard;
        evbuffer_drain(in, discard);
        o->discarding -= discard;
        if (o->discarding) {
            return 0;
        }
        o->state = OF_STATE_READY;
    }
    case OF_STATE_READY: {
        return evbuffer_filter(in, out, ^bool (evbuffer_iovec v) {
            return !obfoo_decrypt(o, v.iov_base, v.iov_base, v.iov_len);
        });
    }
    }
}

ssize_t obfoo_output_filter(obfoo *o, evbuffer *in, evbuffer *out)
{
    //debug("%s: o:%p state:%d incoming:%d\n", __func__, o, o->state, o->incoming);
    switch(o->state) {
    default:
        return 0;
    case OF_STATE_DISCARD:
    case OF_STATE_READY: {
        return evbuffer_filter(in, out, ^bool (evbuffer_iovec v) {
            return !obfoo_encrypt(o, v.iov_base, v.iov_base, v.iov_len);
        });
    }
    }
}
