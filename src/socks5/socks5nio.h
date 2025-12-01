#ifndef SOCKS5NIO_H
#define SOCKS5NIO_H

#include "selector.h"
/** maquina de estados general */
typedef enum socks_v5state {
    /**
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no esté completo
     *   - HELLO_WRITE cuando está completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envía la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
    HELLO_WRITE,

    REQUEST_READ,
    REQUEST_WRITE,
    COPY,

    // estados terminales
    DONE,
    ERROR,
};

void socksv5_passive_accept(struct selector_key *key);
void socksv5_pool_destroy(void);

#endif
