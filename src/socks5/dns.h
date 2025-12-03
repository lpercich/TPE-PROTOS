#ifndef DNS_RESOLUTION_H
#define DNS_RESOLUTION_H

#include "../lib/selector.h"
#include <netdb.h>
#include <pthread.h>

void * dns_resolve(void* s_key);

#endif