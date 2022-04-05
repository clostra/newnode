#ifndef __BUFFEREVENT_UTP_H__
#define __BUFFEREVENT_UTP_H__

#include "libevent/bufferevent-internal.h"

extern const struct bufferevent_ops bufferevent_ops_utp;

#define BEV_IS_UTP(bevp) ((bevp)->be_ops == &bufferevent_ops_utp)

struct bufferevent *
bufferevent_utp_new(struct event_base *base, utp_context *utp_ctx, utp_socket *utp, int options);
int
bufferevent_utp_connect(struct bufferevent *bev, const struct sockaddr *sa, int socklen);

utp_socket* bufferevent_get_utp(const struct bufferevent *bev);

#endif // __BUFFEREVENT_UTP_H__
