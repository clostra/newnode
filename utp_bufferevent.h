#ifndef __UTP_BUFFEREVENT_H__
#define __UTP_BUFFEREVENT_H__

#include "network.h"


uint64 utp_on_error(utp_callback_arguments *a);
uint64 utp_on_read(utp_callback_arguments *a);
uint64 utp_on_state_change(utp_callback_arguments *a);

int utp_socket_create_fd(event_base *base, utp_socket *s);
void utp_connect_tcp(event_base *base, utp_socket *s, const sockaddr *address, socklen_t address_len);

#endif // __UTP_BUFFEREVENT_H__
