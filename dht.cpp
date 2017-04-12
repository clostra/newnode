#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sodium/crypto_sign.h>

#include <dht.h>
#include <ExternalIPCounter.h>

#include <bencoding.h>
#include <udp_utils.h>

#include "dht.h"


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
        ::sendto(sock, (char*)p, len, flags, (struct sockaddr*)&sa, salen);
    }

    void RefreshBindAddr()
    {
        SOCKADDR_STORAGE sa;
        socklen_t salen = sizeof(sa);
        if (::getsockname(sock, (struct sockaddr *)&sa, &salen) != -1) {
            bind_addr = SockAddr(sa);
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

// XXX: TODO: other platforms
#import <CommonCrypto/CommonDigest.h>
sha1_hash sha1(const byte* buf, int len)
{
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(buf, len, digest);
    return sha1_hash(buf);
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
        SOCKADDR_STORAGE sa = *(const SOCKADDR_STORAGE*)i->ai_addr;
        d->idht->AddBootstrapNode(SockAddr(sa));
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

bool dht_process_udp(dht *d, const byte *buffer, size_t len, const struct sockaddr *to, socklen_t tolen)
{
    SOCKADDR_STORAGE sa = *(const SOCKADDR_STORAGE*)to;
    return d->idht->handleReadEvent(&d->udp_socket, (byte*)buffer, len, SockAddr(sa));
}

bool dht_process_icmp(dht *d, const byte *buffer, size_t len, const struct sockaddr *to, socklen_t tolen)
{
    SOCKADDR_STORAGE sa = *(const SOCKADDR_STORAGE*)to;
    return d->idht->handleICMP(&d->udp_socket, (byte*)buffer, len, SockAddr(sa));
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

void dht_destroy(dht *d)
{
    d->idht->Shutdown();
    d->idht.reset(NULL);
    free(d);
}
