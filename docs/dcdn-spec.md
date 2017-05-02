# Decentralized Content Distribution Network (dCDN)

## WARNING—Evolving draft

This is an early evolving draft of the specification, subject to
substantial change.

## Introduction

dCDN is a mobile SDK that builds a peer-to-peer and a device-to-device
network to deliver web objects.  Each mobile device running an app
incorporating dCDN becomes a part of the network.  The dCDN has several
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

The peer protocol is very definitely subject to change.

The peer protocol is HTTP over LEDBAT, with an additional header.
Range requests are used to get parts of the file.  The content is
authenticated using a public key signature produced by the injector.
The signature is sent in X-Sign header.

X-Sign authenticates the entire file, but does not authenticate any parts.

When an injector first injects the object, it starts sending it before
it has seen the whole thing, and so the signature cannot be sent at the
beginning where headers normally go.  The server SHOULD send the X-Sign
header (footer?) with a last empty chunk then.  The client MAY issue a
HEAD request for the same URL right after the GET to obtain the X-Sign
header in that way.  The injector MUST retain X-Sign mapping so that it
can answer the HEAD request.

When two peers are exchanging data, they have to open two separate
connections to send data in each direction.  This is pretty silly
and is one of the reasons to move away from HTTP.

The direction of change that appears most desirable for the future is
probably some subset of BitTorrent v2, for the unlimited granularity of
verification.

Non-normative note: Technically, the only thing necessary for the injector
to inject the file is to transmit the X-Sign. The client can at that point
fetch the file through an untrusted injector proxy. However, given that to
produce the X-Sign the injector needs the whole might, it makes sense that
it also sends the first copy that the client can later seed to other peers.

## Policy Settings

An app incorporating dCDN MAY change the defaults for policy settings.
In addition, an app MAY expose some or all of these settings to a user
and allow the user to override the app's defaults.  There are, thus,
three levels of decision-making: the dCDN spec, which provides the
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
