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

1 A->B: crypto_kx_PUBLICKEYBYTES, PadA
2 B->A: crypto_kx_PUBLICKEYBYTES, PadB
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
    uint16_t discarding;
    bool incoming:1;
} obfoo;

void bufferevent_set_readcb(bufferevent *bev, bufferevent_data_cb read_cb)
{
    bufferevent_data_cb write_cb;
    bufferevent_event_cb event_cb;
    void *ctx;
    bufferevent_getcb(bev, NULL, &write_cb, &event_cb, &ctx);
    bufferevent_setcb(bev, read_cb, write_cb, event_cb, ctx);
}

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

void obfoo_write_encrypt(obfoo *o, bufferevent *bev, uint8_t *b, size_t len)
{
    uint8_t c[len];
    if (obfoo_encrypt(o, c, b, len)) {
        return;
    }
    bufferevent_write(bev, c, len);
}

void bufferevent_read_min(bufferevent *bev, size_t len, bufferevent_data_cb read_cb)
{
    debug("%s reading:%llu\n", __func__, len);
    bufferevent_setwatermark(bev, EV_READ, len, 0);
    bufferevent_set_readcb(bev, read_cb);
    evbuffer *in = bufferevent_get_input(bev);
    if (evbuffer_get_length(in) > 0 && evbuffer_get_length(in) >= len) {
        void *ctx;
        bufferevent_getcb(bev, NULL, NULL, NULL, &ctx);
        read_cb(bev, ctx);
    }
}

void obfoo_incoming_read_sync(bufferevent *bev, void *ctx);

void obfoo_incoming_read_intro(bufferevent *bev, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    debug("%s o:%p\n", __func__, o);
    assert(o->incoming);
    evbuffer *in = bufferevent_get_input(bev);
    assert(evbuffer_get_length(in) >= INTRO_BYTES);
    uint8_t *other_pk = evbuffer_pullup(in, crypto_kx_PUBLICKEYBYTES);

    if (crypto_kx_server_session_keys(o->rx, o->tx, o->pk, o->sk, other_pk)) {
        debug("suspicious client public key\n");
        bufferevent_free(bev);
        free(o);
        return;
    }

    evbuffer_drain(in, crypto_kx_PUBLICKEYBYTES);
    bufferevent_read(bev, o->rx_nonce, sizeof(o->rx_nonce));

    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(o->synchash));
    crypto_generichash_update(&state, (const uint8_t *)"req1", strlen("req1"));
    crypto_generichash_update(&state, o->rx, sizeof(o->rx));
    crypto_generichash_final(&state, o->synchash, sizeof(o->synchash));

    bufferevent_read_min(bev, sizeof(o->synchash) + sizeof(crypt_intro), obfoo_incoming_read_sync);
}

void obfoo_discard(bufferevent *bev, void *ctx);

void obfoo_incoming_read_sync(bufferevent *bev, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    debug("%s o:%p\n", __func__, o);
    evbuffer *in = bufferevent_get_input(bev);
    assert(evbuffer_get_length(in) >= sizeof(o->synchash) + sizeof(crypt_intro));
    bufferevent_setwatermark(bev, EV_READ, 0, 0);
    evbuffer_ptr f = evbuffer_search(in, (char*)o->synchash, sizeof(o->synchash), NULL);
    if (f.pos == -1) {
        size_t max_len = INTRO_PAD_MAX + sizeof(o->synchash);
        if (evbuffer_get_length(in) >= max_len) {
            debug("synchash not found in %llu (%llu) bytes\n", max_len, evbuffer_get_length(in));
            bufferevent_free(bev);
            free(o);
            return;
        }
        return;
    }
    evbuffer_drain(in, f.pos + sizeof(o->synchash));
    //debug("synchash found!\n");

    assert(!o->rx_ic_bytes);

    size_t len = sizeof(crypt_intro);
    assert(evbuffer_get_length(in) >= len);
    uint8_t *c = evbuffer_pullup(in, len);
    obfoo_decrypt(o, c, c, len);
    uint16_t pad_len = ((crypt_intro*)c)->pad_len;
    evbuffer_drain(in, len);
    // pad,len(ia)
    o->discarding = pad_len + sizeof(uint16_t);
    bufferevent_read_min(bev, o->discarding, obfoo_discard);

    {
        bufferevent_disable(bev, EV_WRITE);

        union {
            uint8_t buf[sizeof(crypt_intro) + PAD_MAX];
            crypt_intro ci;
        } r = {.buf = {0}};
        r.ci.pad_len = randombytes_uniform(PAD_MAX);
        randombytes_buf(r.ci.pad, r.ci.pad_len);
        size_t crypt_len = sizeof(r.ci) + r.ci.pad_len;
        obfoo_encrypt(o, r.buf, r.buf, crypt_len);
        bufferevent_write(bev, r.buf, crypt_len);

        bufferevent_enable(bev, EV_WRITE);
    }

    obfoo_write_encrypt(o, bev, (uint8_t*)"sup man", sizeof("sup man"));
}

void obfoo_read(bufferevent *bev, void *ctx);

void obfoo_discard(bufferevent *bev, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    debug("%s o:%p\n", __func__, o);
    assert(o->discarding);
    evbuffer *in = bufferevent_get_input(bev);
    assert(evbuffer_get_length(in) >= o->discarding);
    o->rx_ic_bytes += o->discarding;
    evbuffer_drain(in, o->discarding);
    o->discarding = 0;
    bufferevent_read_min(bev, 0, obfoo_read);
}

void obfoo_outgoing_read_vc(bufferevent *bev, void *ctx);

void obfoo_outgoing_read_intro(bufferevent *bev, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    debug("%s o:%p\n", __func__, o);
    assert(!o->incoming);
    evbuffer *in = bufferevent_get_input(bev);
    assert(evbuffer_get_length(in) >= INTRO_BYTES);
    uint8_t *other_pk = evbuffer_pullup(in, crypto_kx_PUBLICKEYBYTES);

    if (crypto_kx_client_session_keys(o->rx, o->tx, o->pk, o->sk, other_pk)) {
        debug("suspicious server public key\n");
        bufferevent_free(bev);
        free(o);
        return;
    }

    evbuffer_drain(in, crypto_kx_PUBLICKEYBYTES);
    bufferevent_read(bev, o->rx_nonce, sizeof(o->rx_nonce));

    bufferevent_disable(bev, EV_WRITE);

    uint8_t synchash[SYNC_HASH_LEN];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(synchash));
    crypto_generichash_update(&state, (const uint8_t *)"req1", strlen("req1"));
    crypto_generichash_update(&state, o->tx, sizeof(o->tx));
    crypto_generichash_final(&state, synchash, sizeof(synchash));
    bufferevent_write(bev, synchash, sizeof(synchash));

    // vc,crypto_provide,(uint16_t)len(pad),pad,len(ia)
    union {
        uint8_t buf[sizeof(crypt_intro) + PAD_MAX + sizeof(uint16_t)];
        crypt_intro ci;
    } r = {.buf = {0}};
    r.ci.pad_len = randombytes_uniform(PAD_MAX);
    randombytes_buf(r.ci.pad, r.ci.pad_len);
    size_t crypt_len = sizeof(crypt_intro) + r.ci.pad_len + sizeof(uint16_t);
    obfoo_encrypt(o, r.buf, r.buf, crypt_len);
    bufferevent_write(bev, r.buf, crypt_len);

    bufferevent_enable(bev, EV_WRITE);

    // encrypt vc from the other side
    crypto_stream_chacha20_xor_ic(o->vc, o->vc, sizeof(o->vc), o->rx_nonce, 0, o->rx);

    bufferevent_read_min(bev, sizeof(crypt_intro), obfoo_outgoing_read_vc);
}

void obfoo_outgoing_read_vc(bufferevent *bev, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    debug("%s o:%p\n", __func__, o);
    bufferevent_setwatermark(bev, EV_READ, 0, 0);
    evbuffer *in = bufferevent_get_input(bev);
    assert(evbuffer_get_length(in) >= sizeof(crypt_intro));
    evbuffer_ptr f = evbuffer_search(in, (char*)o->vc, sizeof(o->vc), NULL);
    if (f.pos == -1) {
        size_t max_len = INTRO_PAD_MAX + sizeof(o->vc);
        if (evbuffer_get_length(in) >= max_len) {
            debug("vc not found in %llu (%llu) bytes\n", max_len, evbuffer_get_length(in));
            bufferevent_free(bev);
            free(o);
            return;
        }
        return;
    }
    assert(!o->rx_ic_bytes);
    o->rx_ic_bytes += sizeof(o->vc);
    evbuffer_drain(in, f.pos + sizeof(o->vc));
    //debug("vc found!\n");

    size_t len = member_sizeof(crypt_intro, crypto_provide) + member_sizeof(crypt_intro, pad_len);
    assert(evbuffer_get_length(in) >= len);
    uint8_t *crypto_select = evbuffer_pullup(in, len);
    obfoo_decrypt(o, crypto_select, crypto_select, len);
    uint16_t pad_len = *(uint16_t*)(crypto_select + member_sizeof(crypt_intro, crypto_provide));
    evbuffer_drain(in, len);

    o->discarding = pad_len;
    bufferevent_read_min(bev, o->discarding, obfoo_discard);

    obfoo_write_encrypt(o, bev, (uint8_t*)"hello, world!", sizeof("hello, world!"));
}

void obfoo_read(bufferevent *bev, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    debug("%s o:%p\n", __func__, o);
    evbuffer *in = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(in);
    uint8_t *b = evbuffer_pullup(in, len);
    uint8_t m[len];
    if (obfoo_decrypt(o, m, b, len)) {
        return;
    }
    debug("rcv: [%.*s]\n", (int)len, m);
}

void obfoo_write(bufferevent *bev, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    debug("obfoo_write o:%p\n", o);
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

void obfoo_event(bufferevent *bev, short events, void *ctx)
{
    obfoo *o = (obfoo*)ctx;
    debug("obfoo_event o:%p events:0x%x\n", o, events);
    if (events & BEV_EVENT_CONNECTED) {
        obfoo_write_intro(o, bev);
    }
}

obfoo* obfoo_new()
{
    obfoo *o = alloc(obfoo);
    crypto_kx_keypair(o->pk, o->sk);
    randombytes_buf(o->tx_nonce, sizeof(o->tx_nonce));
    return o;
}

void obfoo_accept(evconnlistener *listener,
    evutil_socket_t fd, sockaddr *address, int socklen,
    void *ctx)
{
    debug("obfoo_accept %p fd:%d\n", ctx, fd);
    event_base *base = evconnlistener_get_base(listener);
    bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    obfoo *o = obfoo_new();
    o->incoming = true;
    bufferevent_setcb(bev, obfoo_incoming_read_intro, obfoo_write, obfoo_event, o);
    bufferevent_setwatermark(bev, EV_READ, INTRO_BYTES, 0);
    obfoo_write_intro(o, bev);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
}

void obfoo_accept_error(evconnlistener *listener, void *ctx)
{
    event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    debug("obfoo_accept_error %d (%s)\n", err, evutil_socket_error_to_string(err));
}

void obfoo_demo(event_base *base)
{
    sockaddr_in sin = {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(5600)};

    evconnlistener *listener = evconnlistener_new_bind(base, obfoo_accept, NULL,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (sockaddr*)&sin, sizeof(sin));
    if (!listener) {
        perror("couldn't create listener");
        return;
    }
    evconnlistener_set_error_cb(listener, obfoo_accept_error);

    obfoo *o = obfoo_new();
    bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, obfoo_outgoing_read_intro, obfoo_write, obfoo_event, o);
    bufferevent_setwatermark(bev, EV_READ, INTRO_BYTES, 0);
    bufferevent_enable(bev, EV_READ);
    bufferevent_socket_connect_hostname(bev, NULL, AF_INET, "127.0.0.1", 5600);

    debug("obfoo init pubkey_len:%d nonce_len:%d seskey_len:%d\n", crypto_kx_PUBLICKEYBYTES, crypto_stream_chacha20_NONCEBYTES, crypto_kx_SESSIONKEYBYTES);
}
