#include <signal.h>

#ifdef __linux__
#include <linux/errqueue.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#endif

#include <errno.h>
#include <stdio.h>

#include "log.h"
#include "utp.h"
#include "dht.h"
#include "network.h"


#ifdef __linux__
typedef struct iovec iovec;
typedef struct msghdr msghdr;
typedef struct cmsghdr cmsghdr;
typedef struct sock_extended_err sock_extended_err;

void icmp_handler(network *n)
{
    for (;;) {
        uint8_t vec_buf[4096];
        uint8_t ancillary_buf[4096];
        iovec iov = { vec_buf, sizeof(vec_buf) };
        sockaddr_storage remote;

        msghdr msg = {
            .msg_name = (sockaddr *)&remote,
            .msg_namelen = sizeof(remote),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_flags = 0,
            .msg_control = ancillary_buf,
            .msg_controllen = sizeof(ancillary_buf)
        };

        ssize_t len = recvmsg(n->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);

        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            pdie("recvmsg");
        }

        socklen_t remote_len = sockaddr_get_length((const sockaddr *)&remote);

        time_t tosleep;
        dht_process_icmp(n->dht, (const byte*)&msg, sizeof(msg), (const sockaddr *)&remote, remote_len, &tosleep);

        for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level != SOL_IP) {
                debug("Unhandled errqueue level: %d\n", cmsg->cmsg_level);
                continue;
            }

            if (cmsg->cmsg_type == IP_RECVERR) {
                ddebug("errqueue: IP_RECVERR, SOL_IP, len %zd\n", cmsg->cmsg_len);
            } else if (cmsg->cmsg_type == IPV6_RECVERR) {
                ddebug("errqueue: IPV6_RECVERR, SOL_IP, len %zd\n", cmsg->cmsg_len);
            } else {
                debug("Unhandled errqueue type: %d\n", cmsg->cmsg_type);
                continue;
            }

            char host[NI_MAXHOST];
            char serv[NI_MAXSERV];
            getnameinfo((const sockaddr *)&remote, remote_len, host, sizeof(host), serv, sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);
            ddebug("Remote host: %s:%s\n", host, serv);

            sock_extended_err *e = (sock_extended_err *)CMSG_DATA(cmsg);

            if (!e) {
                debug("errqueue: sock_extended_err is NULL?\n");
                continue;
            }

            if (e->ee_origin != SO_EE_ORIGIN_ICMP && e->ee_origin != SO_EE_ORIGIN_ICMP6) {
                debug("errqueue: Unexpected origin: %d\n", e->ee_origin);
                continue;
            }

            ddebug(" errno:%d origin:%d type:%d code:%d info:%d data:%d\n",
                e->ee_errno, e->ee_origin, e->ee_type, e->ee_code, e->ee_info, e->ee_data);

            // "Node that caused the error"
            // "Node that generated the error"

            ddebug("msg_flags: %d", msg.msg_flags);
            if (o_debug >= 2) {
                if (msg.msg_flags & MSG_TRUNC)
                    fprintf(stderr, " MSG_TRUNC");
                if (msg.msg_flags & MSG_CTRUNC)
                    fprintf(stderr, " MSG_CTRUNC");
                if (msg.msg_flags & MSG_EOR)
                    fprintf(stderr, " MSG_EOR");
                if (msg.msg_flags & MSG_OOB)
                    fprintf(stderr, " MSG_OOB");
                if (msg.msg_flags & MSG_ERRQUEUE)
                    fprintf(stderr, " MSG_ERRQUEUE");
                fprintf(stderr, "\n");
            }

            if (o_debug >= 3) {
                hexdump(vec_buf, len);
            }

            if (e->ee_type == 3 && e->ee_code == 4) {
                ddebug("ICMP type 3, code 4: Fragmentation error, discovered MTU %d\n", e->ee_info);
                utp_process_icmp_fragmentation(n->utp, vec_buf, len, (const sockaddr *)&remote, remote_len, e->ee_info);
            } else {
                ddebug("ICMP type %d, code %d\n", e->ee_type, e->ee_code);
                utp_process_icmp_error(n->utp, vec_buf, len, (const sockaddr *)&remote, remote_len);
            }
        }
    }
}
#endif
