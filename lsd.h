#ifndef __LSD_H__
#define __LSD_H__

#include "network.h"


void lsd_setup(network *n);
void lsd_send(network *n, bool reply);

#endif // __LSD_H__
