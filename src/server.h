#ifndef SERVER_H
#define SERVER_H

#include "lib/selector.h"
#include "args.h"

/**
 * Handler para aceptar nuevas conexiones SOCKS5.
 * El key->data debe contener un puntero a struct socks5args con la configuración.
 */
void socksv5_passive_accept(struct selector_key *key);

// Alias para compatibilidad (deprecated)
#define echo_service_accept socksv5_passive_accept

#endif