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
void icmp_handler(network *n)
{
    for (;;) {
        unsigned char vec_buf[4096];
        unsigned char ancillary_buf[4096];
        struct iovec iov = { vec_buf, sizeof(vec_buf) };
        sockaddr_in remote;

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &remote;
        msg.msg_namelen = sizeof(remote);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_flags = 0;
        msg.msg_control = ancillary_buf;
        msg.msg_controllen = sizeof(ancillary_buf);

        ssize_t len = recvmsg(n->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);

        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            pdie("recvmsg");
        }

        dht_process_icmp(n->dht, (const byte*) &msg, sizeof(msg), (sockaddr *)&remote, sizeof(remote));

        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_type != IP_RECVERR) {
                debug("Unhandled errqueue type: %d\n", cmsg->cmsg_type);
                continue;
            }

            if (cmsg->cmsg_level != SOL_IP) {
                debug("Unhandled errqueue level: %d\n", cmsg->cmsg_level);
                continue;
            }

            debug("errqueue: IP_RECVERR, SOL_IP, len %zd\n", cmsg->cmsg_len);

            if (remote.sin_family != AF_INET) {
                debug("Address family is %d, not AF_INET?  Ignoring\n", remote.sin_family);
                continue;
            }

            debug("Remote host: %s:%d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));

            struct sock_extended_err *e = (struct sock_extended_err *)CMSG_DATA(cmsg);

            if (!e) {
                debug("errqueue: sock_extended_err is NULL?\n");
                continue;
            }

            if (e->ee_origin != SO_EE_ORIGIN_ICMP) {
                debug("errqueue: Unexpected origin: %d\n", e->ee_origin);
                continue;
            }

            debug("    ee_errno:  %d\n", e->ee_errno);
            debug("    ee_origin: %d\n", e->ee_origin);
            debug("    ee_type:   %d\n", e->ee_type);
            debug("    ee_code:   %d\n", e->ee_code);
            debug("    ee_info:   %d\n", e->ee_info); // discovered MTU for EMSGSIZE errors
            debug("    ee_data:   %d\n", e->ee_data);

            // "Node that caused the error"
            // "Node that generated the error"
            sockaddr *icmp_addr = (sockaddr *)SO_EE_OFFENDER(e);
            sockaddr_in *icmp_sin = (sockaddr_in *)icmp_addr;

            if (icmp_addr->sa_family != AF_INET) {
                debug("ICMP's address family is %d, not AF_INET?\n", icmp_addr->sa_family);
                continue;
            }

            if (icmp_sin->sin_port != 0) {
                debug("ICMP's 'port' is not 0?\n");
                continue;
            }

            debug("msg_flags: %d", msg.msg_flags);
            if (o_debug) {
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
                debug("ICMP type 3, code 4: Fragmentation error, discovered MTU %d\n", e->ee_info);
                utp_process_icmp_fragmentation(n->utp, vec_buf, len, (sockaddr *)&remote, sizeof(remote), e->ee_info);
            } else {
                debug("ICMP type %d, code %d\n", e->ee_type, e->ee_code);
                utp_process_icmp_error(n->utp, vec_buf, len, (sockaddr *)&remote, sizeof(remote));
            }
        }
    }
}
#endif
