#ifndef __ICMP_HANDLER_H__
#define __ICMP_HANDLER_H__

#ifdef __linux__
struct network;
void icmp_handler(network *n);
#endif

#endif // __ICMP_HANDLER_H__
