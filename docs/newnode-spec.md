# NewNode decentralized Content Distribution Network

## WARNING—Evolving draft

This is an early evolving draft of the specification, subject to
substantial change.

## Introduction

NewNode is a mobile SDK that builds a peer-to-peer and a device-to-device
network to deliver web objects.  Each mobile device running an app
incorporating NewNode becomes a part of the network.  The NewNode has several
benefits:
* content delivery is faster;
* content delivery is more reliable;
* under DDoS or another type of disruption previously published resources
  remain available;
* CDN or hosting bill is lower for the app publisher; and
* censorship is circumvented.

## System Overview and Terminology

The system consists of *injectors*, which form a trusted service that runs
in the cloud and of *peers*.  Some peers act as *injector proxies*;
we sometimes, when this is not ambiguous, refer to injector proxies simply
as *proxies*.

Each injector possesses a private injector key. Each peer has a hardcoded
copy of all injector public keys.

The injectors are used to initially obtain content from a web origin and
to place it into the peer-to-peer network.

Peers use the BitTorrent distributed hash table (DHT) to find injectors,
injector proxies, and other peers interested in the same or similar
content.

Peers use Low Extra Delay Background Transport (LEDBAT) in uTP framing to
connect to one another, as well as to injector proxies and injectors.  The
peer-to-peer and device-to-device connections are called *transport
connections* and run the *peer protocol*.

## Injector Behavior

The injector is a Linux daemon that runs in the cloud.  When an instance
of an injector starts, it SHOULD announce its IP and port in the
BitTorrent DHT in the *injector swarm*, `SHA1("injectors")`, to make
itself easier to find.  It SHOULD accept transport connections from peers
and injector proxies.

### Injector Verification Challenge

A peer may challenge an injector or an injector proxy. Successful response
to the challenge verifies that the challenged entity can connect to (or is)
an injector.

To avoid pointlessly fetching external URLs, the `TRACE` method is used.
The little-used method echoes back its request. Since the injector signs
its responses with the X-Sign header, the response is guaranteed to have
come from an injector if the challenge is unique. The challenge includes
a cryptographically secure random nonce.

The format of the challenge is `TRACE /`⟨uuid⟩` HTTP/1.1`. The response is
the echoed request with an added X-Sign header.

## Peer Behavior

A peer performs some actions on start and some actions for each web
request.

### Peer Behavior on Start

When a peer starts, it connects to an injector and, if successful, becomes
a proxy.  If not successful, it connects to a proxy instead.  This works
as follows.

#### Connect to an Injector

When a peer starts, it SHOULD try to connect to an injector.  To do so,
it SHOULD find injectors using the following methods:
1. read the injector swarm (using the `announce_only_get` flag),
2. use hardcoded IPs and ports,
3. use IPs and ports cached from previous runs, and
4. use peer exchange for the injector swarm.

After connecting to an injector, a peer MAY verify that the injector
is real using the injector verification challenge.

#### Become a Proxy, or Connect to One

If the peer connected to an injector successfully, the peer SHOULD
start acting as an injector proxy.

If the peer failed to connect to an injector, the peer SHOULD connect to
an injector proxy.  To find an injector proxy, the peer SHOULD use the
following methods:
1. read the injector proxy swarm (`SHA1("injector proxies")`),
2. use IPs and ports cached from previous runs, and
3. use peer exchange for the injector proxy swarm.

### Peer Behavior on Request

When a peer gets a request for a web object identified by a URL from
the app, it SHOULD immediately open an origin connection and try to start
getting the object as usual using HTTP or HTTPS.  The peer MUST
differentiate between static and dynamic requests.  Static requests
are those where the content is public and would be usable by many
other people requesting the same URL.  Dynamic requests are those
that return private or personalized content.  For example, the front page
of The New York Times is static, while the Facebook feed is
dynamic.  The peer MAY treat `GET` requests as static and `POST` as
dynamic.  This is the bare minimum for differentiating between the two.
The peer SHOULD have substantially more sophisticated heuristics than
the minimum GET/POST difference.

Note that static resources may be mutable.  It is not the immutability,
but scope of permitted and useful applicability that makes a resource
static.

#### Peer Behavior on Static Request

In addition to the origin connection, the peer SHOULD immediately
announce on the *URL swarm* (see next paragraph) and start trying to
establish up to 1 peer connection.

Each URL has an associated swarm used to find other peers interested in
this content.  The URL swarm is currently `SHA1(url)`.  It is anticipated
that this will change in a future protocol version due to two different
concerns: DHT scalability and security.  (Watch this space for a new
version.)

If there's no-one found on the URL swarm who has a valid unexpired
*URL content signature*, the peer SHOULD ask an injector or an injector
proxy, whichever the peer is connected to, to inject the URL.

The peer SHOULD remain in the URL swarm after download is finished and
until the soonest of the following:
* max seed ratio is reached,
* the signature expires,
* the signature becomes obsolete due to the presence of a newer signature,
* one week elapses, or
* the content is deleted from OS cache or due to space constraints.

The peer MAY suspend participation in the swarm due to resource, battery,
or policy constraints.  When such constraints are lifted, the peer SHOULD
resume seeding.

#### Peer Behavior on Dynamic Request

If the peer is successful in communicating with the origin, it SHOULD
simply get the response from the origin and not involve the peer-to-peer
network.  If that does not work, the peer SHOULD use an injector proxy
and use the `CONNECT` method to reach the origin.  In either case, there
SHOULD NOT be any byte range splitting as dynamic requests often have
non-idempotent side effects.  The peer SHOULD cache the method by which
it has received the last dynamic response from a given domain and reuse
it to avoid multiple timeouts when origin is not available directly, but
available through a proxy.

## Injector Proxy Behavior

The injector proxy SHOULD forward peer protocol requests to the
injector and MAY serve CONNECT method requests.

## Peer Protocol

The peer protocol is subject to evolution as we further experiment with it in
the next few months.

The peer protocol is essentially HTTP over LEDBAT, with an some additional
headers and verbs.
In addition, the HTTP exchange is protected by a layer of transport
encryption, to make surveillance and blocking harder. This layer is
inspired by BitTorrent Message Stream Encryption and has similar security
properties, providing a better-than-nothing security that substantially
raises attack costs from typing a few line into DPI configuration to
spending hundreds of million on new equipment. We use more modern
primitives than BitTorrent Message Stream Encryption.

Range requests are used to get parts of the file.  The content is
authenticated using a Merkle tree, the root of which is signed by the injector.
The signature for the root of the tree is sent in X-MSign header.

X-MSign authenticates any suitably sized parts of the file being transmitted.

When an injector first injects the object, it starts sending it before
it has seen the whole thing, and so the signature cannot be sent at the
beginning where headers normally go.  The injector SHOULD send the X-MSign
header as a trailed with a last empty chunk then.

When two peers are exchanging data, they have to open at least two separate
connections to send data in each direction. They MAY open more LEDBAT
connections in each direction to transmit parts of the file.

Non-normative note: Technically, the only thing necessary for the injector
to inject the file is to transmit the X-MSign. The client can at that point
fetch the file through an untrusted injector proxy. However, given that to
produce the X-MSign the injector needs the whole might, it makes sense that
it also sends the first copy that the client can later seed to other peers.

### Merkle Tree

Similar to BEP 52, a Merkle tree is constructed for the file, with a branching
factor of 2, constructed from 16KiB blocks of the file. The last block may be
shorter than 16KiB. The remaining leaf hashes beyond the end of the file
required to construct upper layers of the Merkle tree are set to zero.

Here, the digest function is the default hash primitive in libsodium.

### X-MSign Format

X-MSign replaces a previously used X-Sign header. X-Sign was an older mechanism
we used. It authenticated the entire file, but did not authenticate any parts.

X-MSign is a signed message that consists of the ASCII characters "msign" (5
bytes), timestamp when the message was generated (4 bytes), and of the
root-level of the Merkle tree. The content includes HTTP headers other than
X-Sign. The headers whenever peer protocol is used MUST include Content-Location
and Content-Length, so that the URL and size is authenticated.

X-MSign is transmitted base-64 encoded.

In other words,

```http
X-MSign: <base64(sign("msign" + timestamp + merkel_tree_root(headers + content)))>
```

Here, `sign()` is the default primitives in libsodium.

### X-HashRequest

The presence of the X-HashRequest header indicates, from one peer to another,
that the response to a request (or range request) should contain the X-MSign and
leaf-level Merkle tree nodes so that the content can be validated. A peer only
needs to request this once.

### X-Hashes

The X-Hashes header is sent in response to a request which contains
X-HashRequest, and X-Hashes contains the base-64 encoded leaf-level Merkle tree
node.

```http
X-Hashes: <base64([leaf, leaf, leaf, ...])>
```

### Range requests

With a Merkle tree authenticating the entire file, normal HTTP Range requests
can be used to fetch parts of the content from different peers. It is necessary
to have aligned 16KiB chunks in order to check the leaf level hash, and so
requests on 16KiB boundaries of 16KiB multiple lengths SHOULD be used.

### HAVE

As peers receive and hash validate chunks, or delete them from disk, they update
a bitfield of chunks they have available to send to other peers. A new HTTP
verb, HAVE, allows a requester to notify another peer about the updated
bitfield. This should only be sent to peers who have previously requested the
same content. It is not necessary to send an updated bitfield to a peer who also
claims to have the chunks involved in the update. The bitfield itself is sent as
base64 of bitfield in the X-Bitfield header. A peer may send their X-Bitfield in
response to a normal GET request, as well.

Example:

```http
HAVE <content-uri> HTTP/1.1
X-Bitfield: <base64(bitfield)>

```

### Gossip

While sending responses, a peer may include endpoints for other peers who also
requested the same content. When received, these endpoints may be used as
additional peers. They are sent as base64 of the compacted IP addresses:

```http
X-Peers4: <base64([ipv4,port, ...])>
X-Peers6: <base64([ipv6,port, ...])>
```

### Transport Encryption

The following protocol describes a protocol layer for bidirectional
data streams that prevents passive eavesdropping and thus protocol or
content identification. We use it in NewNode with uTP/LEDBAT, but it is
equally applicable to TCP.

The protocol looks like random bytes right from the first byte and has no
packets of characteristic lengths below maximum.

Note that the major design goal is payload and protocol obfuscation, not
authentication and data integrity verification. Thus the protocol does not offer
protection against active adversaries. An attacking party can connect to the
peers, while blocking their direct communication, and run a MITM attack. This is
substantially more expensive for the attacker than passive observation, as it
requires, at minimum, equipment that can identify the relevant streams despite
their lack of outward features and implements the NewNode Transport Encryption
protocol, as described in this section.

There are two peers, *A* and *B*, with *A* connecting to *B*.

First, let us introduce some constants.

Below, `VC` is a verification constant that defeats replay attacks.

The fields `crypto_provide` and `crypto_select` are a 32-bit bitfields. As of
now, `0x1` means ChaCha20 from the NaCl suite. The remaining 31 bits are
reserved for future use: they MUST be set to 0 by *A* and MUST be ignored by
*B*.

The initiating peer *A* SHOULD provide all methods it supports in the bitfield,
but MAY choose only to provide higher encryption levels. The responding peer *B*
MUST set a bit corresponding to the single method which it selected from the
provided ones.

Other constants used below:
```
crypto_kx_PUBLICKEYBYTES = 32
crypto_stream_chacha20_NONCEBYTES = 8
crypto_stream_chacha20_KEYBYTES = 32
crypto_kx_SESSIONKEYBYTES = 32
BLAKE2B_BYTES = 40
INTRO_BYTES = crypto_kx_PUBLICKEYBYTES + crypto_stream_chacha20_NONCEBYTES
PAD_MAX = 256
INTRO_PAD_MAX = (96 + PAD_MAX) - INTRO_BYTES
STREAM_BLOCK_LEN = 64
VC = "\x00\x00\x00\x00\x00\x00\x00\x00"
VC_BYTES = 8
crypto_provide = "\x01\x00\x00\x00"
CRYPTO_PROVIDE_BYTES = 4
encode_length(len) = len as two-byte unsigned little-endian integer
decode_length(uint16) = invert encode_length
```

The maximum length that can be specified is 65535 bytes. The function
`decode_len` is a no-op and unnecessary if the implementation only runs on a
little-endian architecture.

We use primitives from the NaCl suite. We use the libsodium implementation of
NaCl. Other interoperable and secure implementations of NaCl MAY be used.
We refer to C versions of NaCl functions below. Bindings for C++ (or other
languages in future) MAY be used as long as the wire format is not changed.
The wire format MUST be the same for interoperability.

First, *A* makes a keypair:
```
crypto_kx_keypair(a_public_key, a_secret_key)
```

And a `tx` nonce:
```
randombytes_buf(a_tx_nonce, crypto_stream_chacha20_NONCEBYTES)
```

And a random length pad of random bytes:
```
pad_length = randombytes_uniform(INTRO_PAD_MAX)
a_pad = random_bytes(pad_length)
```

Other random distributions of `pad_length` MAY be used, including ones that
are biased towards smaller values, such as clipped Poisson or clipped integer
exponential.

Then, *A* sends those:
```
send(a_public_key)
send(a_tx_nonce)
send(a_pad)
```

Then *A* waits for response.

*B* also makes a keypair:
```
crypto_kx_keypair(b_public_key, b_secret_key)
```

And a `tx` nonce:
```
randombytes_buf(b_tx_nonce, crypto_stream_chacha20_NONCEBYTES)
```

*B* reads `crypto_kx_PUBLICKEYBYTES` bytes, and stores it as *A*'s public key:
```
b_other_public_key = recv(crypto_kx_PUBLICKEYBYTES)
```

*B* generates session keys, `b_rx` and `b_tx`:
```
crypto_kx_server_session_keys(b_rx, b_tx, b_public_key, b_secret_key, b_other_public_key)
```

*B* reads `crypto_stream_chacha20_NONCEBYTES` bytes, and stores them as the `rx`
nonce:
```
b_rx_nonce = recv(crypto_stream_chacha20_NONCEBYTES)
```

And a random length pad of random bytes:
```
pad_length = randombytes_uniform(INTRO_PAD_MAX)
b_pad = random_bytes(pad_length)
```

Like *A*, *B* MAY use a different distribution for `pad_length`.

Then, *B* sends his introduction:
```
send(b_public_key)
send(b_tx_nonce)
send(b_pad)
```

Then *B* waits for response.

*A* reads `crypto_kx_PUBLICKEYBYTES` bytes, and stores them as *B*'s public key:
```
a_other_public_key = recv(crypto_kx_PUBLICKEYBYTES)
```

*A* generates session keys, `a_rx` and `a_tx`:
```
crypto_kx_client_session_keys(a_rx, a_tx, a_public_key, a_secret_key, a_other_public_key)
```

At this point, `a_rx == b_tx` and `a_tx == b_rx`.

*A* receives `crypto_stream_chacha20_NONCEBYTES` bytes, and stores them as the
`rx` nonce:
```
a_rx_nonce = recv(crypto_stream_chacha20_NONCEBYTES)
```

Then, *A* generates a *sync hash*:
```
a_sync_hash = BLAKE2b("req1" ‖ a_tx)
```
Here and below, `‖` means concatenation.

And a random length padding of random bytes:
```
a_pad2_length = randombytes_uniform(PAD_MAX)
a_pad2 = random_bytes(a_pad2_length)
```

Then, *A* sends:
```
send(sync_hash)
```

At this point, *A* starts encrypting everything it sends.
To encrypt `plain_text`, *A* uses:
```
crypto_stream_chacha20_xor_ic_bytes(cipher_text, plain_text, plain_text_len, a_tx_nonce, a_tx_ic, a_tx)
```
or, for short `ENCRYPT(plain_text)`.

*A* increases the block counter `a_tx_ic` by one after every 64 bytes are
encrypted.

*A* sends (now encrypted):
```
encrypt_send(VC)
encrypt_send(crypto_provide)
encrypt_send(encode_length(a_pad2_length))
encrypt_send(a_pad2)
```

Here, `encrypt_send` sends the bytes having first encrypted them.

Note that because there's nothing happening besides switching encryption on
between sending `sync_hash` and this block of bytes, they will normally be
sent by the underlying transport protocol as a part of the same network packet.

Then *A* waits.

*B* reads bytes from *A*, including the pad of unknown length (`a_pad`).
To find the end of the pad, B generates the *sync hash*:
```
b_sync_hash = BLAKE2b("req1" ‖ b_rx)
```

(Note that since `b_rx == a_tx`, *A* and *B* have the same sync hash:
`a_sync_hash == b_sync_hash`.)

Then *B* discards bytes until it finds the sync hash, or exceeds the limit:
```
max_recv = INTRO_PAD_MAX + BLAKE2B_BYTES
found = recv_until(b_sync_hash, max_recv)
if (!found) close()
```

Once found, *B* treats all future bytes as encrypted.

To decrypt them, it initializes block counters to zero:
```
b_rx_ic = 0
```

*B* uses ChaCha20 with the `rx` nonce (`b_rx_nonce`) and `rx` session key
(`b_rx`):

```
crypto_stream_chacha20_xor_ic(plain_text, cipher_text, cipher_text_len, b_rx_nonce, b_rx_ic, b_rx)
```

Since ChaCha20 uses 64 byte blocks, the block counter b_rx_ic is increased by
one after every 64 bytes are decrypted.

Similarly, to encrypt `plain_text`, *B* uses:
```
crypto_stream_chacha20_xor_ic_bytes(cipher_text, plain_text, plain_text_len, b_tx_nonce, b_tx_ic, b_tx)
```
or, for short, `ENCRYPT(plain_text)`.

Block counter `b_tx_ic` is increased by one after every 64 bytes are encrypted.

*B* then receives (and decrypts) `VC_BYTES` bytes, and checks to see if it is
valid:
```
vc = decrypt_recv(VC_BYTES)
if (vc != VC) close()
```

Then *B* receives the requested crypto cipher (presently only one,
`crypto_provide`, is supported):
```
crypto_select = decrypt_recv(CRYPTO_PROVIDE_BYTES)
```

*B* generates a random length pad of random bytes:
```
b_pad2_length = randombytes_uniform(PAD_MAX)
b_pad2 = random_bytes(a_pad2_length)
```

Then, *B* sends a response:
```
send(b_sync_hash)
encrypt_send(VC)
encrypt_send(crypto_provide)
encrypt_send(encode_length(b_pad2_length))
encrypt_send(b_pad2)
```

At this point *B* is ready to send encrypted application bytes.

Then *B* receives the pad length, and discards pad_length bytes:
```
pad_length = decode_len(recv(2))
decrypt_recv(pad_length)
```

Now *B* is ready to receive and decrypt application bytes.

*A* receives bytes from *B*, including the padding of unknown length (`b_pad`).
To find the end of the padding, A generates `VC` as it would appear
encrypted from `B`:
```
a_rx_ic = 0
crypto_stream_chacha20_xor_ic(a_vc, VC, VC_BYTES, a_rx_nonce, a_rx_ic, a_rx)
```

Then *A* discards bytes until it finds `a_vc`, or exceeds the limit:
```
max_recv = INTRO_PAD_MAX + VC_BYTES
found = recv_until(a_vc, max_recv)
if (!found) close()
```

Once found, *A* treats all future bytes as encrypted. To decrypt them, it
continues using the `rx` block counter from earlier (`a_rx_ic`) and uses
ChaCha20 with the rx nonce (`a_rx_nonce`) and rx session key (`a_rx`):
```
crypto_stream_chacha20_xor_ic(plain_text, cipher_text, cipher_text_len, a_rx_nonce, a_rx_ic, a_rx)
```

Since ChaCha20 uses 64 byte blocks, the block counter `a_rx_ic` is increased by
one after every 64 bytes are decrypted.

At this point *A* is ready to send encrypted application bytes.

Then *A* receives the requested crypto cipher (presently only one,
`crypto_provide`, is supported):
```
crypto_select = decrypt_recv(CRYPTO_PROVIDE_BYTES)
```

Then *A* receives the padding length, and discards `pad_length` bytes:
```
pad_length = decode_len(recv(2))
decrypt_recv(pad_length)
```

Now *A* is ready to receive and decrypt application bytes.

A quick summary of the above. On the wire, the handshake is separated into five
blocking steps:
1. *A*→*B*: `a_public_key ‖ a_tx_nonce ‖ a_pad`
2. *B*→*A*: `b_public_key ‖ b_tx_nonce ‖ b_pad`
3. *A*→*B*: `BLAKE2b('req1', tx) ‖ ENCRYPT(VC ‖ crypto_provide ‖ encode_len(a_pad2_length) ‖ a_pad2)`
4. *B*→*A*: `ENCRYPT2(VC ‖ crypto_select ‖ encode_len(b_pad2_length) ‖ b_pad2) ‖ ENCRYPT(Payload Stream)`
5. *A*→*B*: `ENCRYPT2(Payload Stream)`

Here, `ENCRYPT2` is currently the same as `ENCRYPT` and may change in future
if more ciphers are supported.

Since the lengths of `a_pad` and `b_pad` are unspecified on the wire, *B* will
resynchronize on `HASH('req1', tx)` while *A* will resynchronize on
`ENCRYPT(VC)`.

## Policy Settings

An app incorporating NewNode MAY change the defaults for policy settings.
In addition, an app MAY expose some or all of these settings to a user
and allow the user to override the app's defaults.  There are, thus,
three levels of decision-making: the NewNode spec, which provides the
defaults suitable for the widest variety of apps, an app developer,
who can change the defaults to what makes the most sense for the specific
app and its users, and, finally, the user.

The list of policy settings and their defaults is as follows:
* connect to origin (default: ON)
* act as a proxy (default: ON)
* only act as a proxy on Wi-Fi (default: ON)
* only act as a proxy when plugged into external power (default: ON)
* encrypt peer connections (default: the inverse of connect to origin)
* max seed ratio (default: 3)
* max storage (NO default, use OS cache)

## DHT Scalability Considerations

### Injector Swarm

### Injector Proxy Swarm

### Swarms/Nodes Ratio

## Battery Considerations

## FAQ

### Why Not BEP 44?

### Why Not Onion Routing?

### Why Not a DHT Protocol Flag to Signify Proxies?

### Why Not BitTorrent Peer Protocol?

### What is BitTorrent v2?

### Why a Single Transport Swarm?

### Why LEDBAT?

### What's the Density Required for Device-to-Device Connections?

## Security Considerations

### SHA1 is Broken

### Private Content

### CONNECT in Proxy
