#ifndef SERVER_H
#define SERVER_H

#include "lib/selector.h"

/**
 * Handler para aceptar nuevas conexiones del Echo Server.
 */
void echo_service_accept(struct selector_key *key);

#endif