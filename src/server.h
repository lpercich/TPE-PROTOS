#ifndef SERVER_H
#define SERVER_H

#include "args.h"
#include "lib/selector.h"

/**
 * Handler para aceptar nuevas conexiones SOCKS5.
 * El key->data debe contener un puntero a struct socks5args con la
 * configuración.
 */
void socksv5_passive_accept(struct selector_key *key);

const struct fd_handler *get_session_handler(void);
extern const struct fd_handler session_handlers;

struct client_s; // Forward declaration
// Session cleanup function (client_t defined in socks5.h)
void session_destroy(struct client_s *session);

// Alias para compatibilidad (deprecated)
#define echo_service_accept socksv5_passive_accept

#endif