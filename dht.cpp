#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sodium/crypto_sign.h>

#include <dht.h>
#include <ExternalIPCounter.h>

#include <bencoding.h>
#include <udp_utils.h>

extern "C" {
#include "dht.h"
#include "sha1.h"
}


struct udp_socket : UDPSocketInterface
{
    void Send(const SockAddr& dest, cstr host, const byte *p, size_t len, uint32 flags = 0)
    {
        // no support for sending to a hostname
        assert(false);
    }

    void Send(const SockAddr& dest, const byte *p, size_t len, uint32 flags = 0)
    {
        socklen_t salen;
        const SOCKADDR_STORAGE sa(dest.get_sockaddr_storage(&salen));
        ::sendto(sock, (char*)p, len, flags, (sockaddr*)&sa, salen);
    }

    void RefreshBindAddr()
    {
        SOCKADDR_STORAGE sa;
        socklen_t salen = sizeof(sa);
        if (::getsockname(sock, (sockaddr *)&sa, &salen) != -1) {
            bind_addr = SockAddr((const sockaddr &)sa);
        }
    }

    const SockAddr& GetBindAddr() const { return bind_addr; }

    int sock;
    SockAddr bind_addr;
};

void save_dht_state(const byte* buf, int len)
{
    FILE *f = fopen("dht.dat", "wb");
    if (f) {
        fwrite(buf, len, 1, f);
        fclose(f);
    }
}

void load_dht_state(BencEntity* ent)
{
    FILE *f = fopen("dht.dat", "rb");
    if (!f) {
        return;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char*)malloc(fsize);
    fread(buf, fsize, 1, f);
    fclose(f);

    BencEntity::Parse((uint8_t *)buf, *ent, (unsigned char*)buf + fsize);

    free(buf);
}

bool ed25519_verify(const uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *key)
{
    return crypto_sign_verify_detached(signature, message, message_len, key) == 0;
}

void ed25519_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *key)
{
    crypto_sign_detached(signature, NULL, message, message_len, key);
}

sha1_hash sha1(const byte* buf, int len)
{
    uint8_t digest[20];
    SHA1(digest, buf, len);
    return sha1_hash(digest);
}

struct dht {
    dht() : external_ip(sha1) {}
    smart_ptr<IDht> idht;
    udp_socket udp_socket;
    ExternalIPCounter external_ip;
};

void add_bootstrap(dht *d, const char* address, const char* port)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *res;
    int error = getaddrinfo(address, port, &hints, &res);
    if (error) {
        printf("getaddrinfo: %s\n", gai_strerror(error));
        return;
    }
    for (struct addrinfo* i = res; i; i = i->ai_next) {
        d->idht->AddBootstrapNode(SockAddr(i->ai_addr));
    }
    freeaddrinfo(res);
}

dht* dht_setup(int fd)
{
    dht *d = new dht();
    d->udp_socket.sock = fd;
    d->udp_socket.RefreshBindAddr();
    d->idht = create_dht(&d->udp_socket, &d->udp_socket, &save_dht_state, &load_dht_state, &d->external_ip);
    d->idht->SetSHACallback(&sha1);
    d->idht->SetEd25519SignCallback(&ed25519_sign);
    d->idht->SetEd25519VerifyCallback(&ed25519_verify);
    d->idht->SetVersion("dc", 0, 1);
    // ping 6 nodes at a time, whenever we wake up
    d->idht->SetPingBatching(6);

    add_bootstrap(d, "router.utorrent.com", "6881");
    add_bootstrap(d, "router.bittorrent.com", "6881");

    d->idht->Enable(true, 8000);

    return d;
}

void dht_tick(dht *d)
{
    d->idht->Tick();
}

bool dht_process_udp(dht *d, const byte *buffer, size_t len, const sockaddr *to, socklen_t tolen)
{
    return d->idht->handleReadEvent(&d->udp_socket, (byte*)buffer, len, SockAddr(to));
}

bool dht_process_icmp(dht *d, const byte *buffer, size_t len, const sockaddr *to, socklen_t tolen)
{
    return d->idht->handleICMP(&d->udp_socket, (byte*)buffer, len, SockAddr(to));
}

void add_nodes_cb(void *ctx, const byte *info_hash, const byte *peers, uint num_peers)
{
    add_nodes_callblock cb = (add_nodes_callblock)ctx;
    cb(peers, num_peers);
    if (!peers) {
        Block_release(cb);
    }
}

void dht_announce(dht *d, const byte *info_hash, add_nodes_callblock cb)
{
    cb = Block_copy(cb);
    d->idht->AnnounceInfoHash(info_hash, add_nodes_cb, NULL, NULL, cb, 0);
}

void dht_get_peers(dht *d, const byte *info_hash, add_nodes_callblock cb)
{
    cb = Block_copy(cb);
    d->idht->AnnounceInfoHash(info_hash, add_nodes_cb, NULL, NULL, cb, IDht::announce_only_get);
}

typedef int (^put_callblock)(std::vector<char>& buffer, int64& seq, SockAddr src);

typedef struct {
    put_callblock put_cb;
    put_complete_callblock put_complete_cb;
} put_context;

int put_cb(void *ctx, std::vector<char>& buffer, int64& seq, SockAddr src)
{
    put_context *p = (put_context*)ctx;
    int r = p->put_cb(buffer, seq, src);
    Block_release(p->put_cb);
    return r;
}

void put_complete_cb(void *ctx)
{
    put_context *p = (put_context*)ctx;
    p->put_complete_cb();
    Block_release(p->put_complete_cb);
    free(p);
}

void dht_put(dht *d, const byte *pkey, const byte *skey, const char *v, int64 seq, put_complete_callblock cb)
{
    put_context *p = (put_context *)malloc(sizeof(put_context));
    p->put_cb = ^int (std::vector<char>& buffer, int64& found_seq, SockAddr src) {
        buffer.assign(v, v + strlen(v));
        return 0;
    };
    p->put_cb = Block_copy(p->put_cb);
    p->put_complete_cb = Block_copy(cb);
    d->idht->Put(pkey, skey, put_cb, put_complete_cb, NULL, p, 0, seq);
}

void dht_destroy(dht *d)
{
    d->idht->Shutdown();
    d->idht.reset(NULL);
    free(d);
}
