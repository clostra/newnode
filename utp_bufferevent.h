#ifndef __UTP_BUFFEREVENT_H__
#define __UTP_BUFFEREVENT_H__

#include "network.h"


uint64 utp_on_read(utp_callback_arguments *a);
uint64 utp_on_state_change(utp_callback_arguments *a);

int utp_socket_create_fd_interface(event_base *base, utp_socket *s);

#endif // __UTP_BUFFEREVENT_H__
