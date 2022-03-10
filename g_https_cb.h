#ifndef __G_HTTPS_CB__
#define __G_HTTPS_CB__

#include "network.h"

// Generic types of error that an HTTPS GET can result in.
//
// It's not strictly necessary for the g_https_cb implementation to be
// able to perfectly distinguish between all of these.  It just needs
// to be able to report error conditions well enough to allow NewNode
// to distinguish between potentially censored/blocked servers and
// unblocked ones.  But blocking can manifest itself in various ways:
// IP traffic blocking probably looks like a timeout, blocking by DNS
// can either look like a failed lookup, a lookup that returns no
// information (which isn't a failure), or a lookup that returns false
// information.  If the firewall blocks by sending an ICMP unreachable
// packet or by sending TCP RST packets, this may appear as an i/o
// error on the socket.  If the firewall blocks by sending the traffic
// to an imposter https server, the certificate verification will
// generally fail (unless the censor has a certificate from a
// certificate authority that is trusted by the client).  Another way
// of blocking is for the firewall to insert bogus data into the TLS
// stream which will generally cause a TLS protocol error.
// 
// One error that is NOT a sign of blocking is an HTTP error like 404.
// Receiving an HTTP error generally means that the encrypted
// connection to the origin server succeeded.  However error 451 is an
// exception, because it specifically indicates server-side content
// blocking.

typedef enum {
    // don't change these error codes, they're used to log to stats.newnode.com
    HTTPS_NO_ERROR = 0,
    HTTPS_DNS_ERROR = 2,                // dns lookup failure
    HTTPS_HTTP_ERROR = 3,               // http error code returned FROM ORIGIN SERVER
                                        // (except for codes like 451 that indicate server-side blocking)
    HTTPS_TLS_ERROR = 4,                // unspecific TLS error (e.g. version incompatibility)
    HTTPS_TLS_CERT_ERROR = 5,           // TLS cert verification error
    HTTPS_SOCKET_IO_ERROR = 6,          // any kind of TCP read/write error
    HTTPS_TIMEOUT_ERROR = 7,            // timeout exceeded
    HTTPS_PARAMETER_ERROR = 8,          // error in some parameter passed to g_https_cb
    HTTPS_SYSCALL_ERROR = 9,            // error from system call
    HTTPS_GENERIC_ERROR = 10,           // error not indicative of blocking not otherwise listed
    HTTPS_BLOCKING_ERROR = 11,          // error indicative of blocking not otherwise listed
    HTTPS_RESOURCE_EXHAUSTED = 12       // ran out of some resource
} https_error;

typedef struct https_request {
    char *buf;
    size_t bufsize;
    int flags;
#define HTTPS_DIRECT 01
#define HTTPS_USE_HEAD 020
#define HTTPS_ONE_BYTE 040
#define HTTPS_NO_REDIRECT 0100
#define HTTPS_NO_RETRIES 0200
#define HTTPS_OPTION_MASK (HTTPS_DIRECT|HTTPS_USE_HEAD|HTTPS_ONE_BYTE|HTTPS_NO_REDIRECT|HTTPS_NO_RETRIES)
#define HTTPS_TRYFIRST_FLAGS (HTTPS_DIRECT|HTTPS_ONE_BYTE|HTTPS_NO_REDIRECT|HTTPS_NO_RETRIES)
#define HTTPS_STATS_FLAGS (0)
#define HTTPS_GEOIP_FLAGS (HTTPS_DIRECT)
    int timeout_sec;
} https_request;

typedef struct https_result {
    char *response_body;                // may be heap or stack allocated, valid only for
                                        // duration of completion callback, MUST NOT be freed
                                        // by completion callback
    size_t response_length;
    int result_flags;
#define HTTPS_RESULT_TRUNCATED 02
#define HTTPS_REQUEST_USE_HEAD 04        // copied from request
#define HTTPS_REQUEST_ONE_BYTE 010        // copied from request
    time_t req_time;
    uint64_t xfer_start_time_us;
    uint64_t xfer_time_us;
    https_error https_error;
    int http_status;                    // 3-digit http status code (0 if unknown)
    int64_t request_id;
} https_result;

void cancel_https_request(network *n, int64_t request_id);

#endif // __G_HTTPS_CB__
