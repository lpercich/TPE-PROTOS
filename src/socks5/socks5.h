#ifndef SOCKS5_H
#define SOCKS5_H
#define BUFFER_SIZE 4096  
#include "auth.h"
#include "hello.h"
#include "stm.h"
#include "request.h"

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
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_WRITE,
    COPY,

    // estados terminales
    DONE,
    ERROR,
}socks_v5state;

typedef struct {
    enum socks_v5state state;
    int client_fd;
    int origin_fd;

    //buffers de read y write
    buffer read_buffer;
    buffer write_buffer;

    /* union {
        struct hello_parser hello_st;
        request_parser request_st;
    }parsers; */



    //memoria para los buffers
    uint8_t read_memory[BUFFER_SIZE];
    uint8_t write_memory[BUFFER_SIZE];

    //estado en el que se encuentra la lectura/parseo
    struct state_machine stm;

    //Parsers y datos de estado
    struct hello_parser hello_parser;
    uint8_t chosen_method;

    struct auth_parser auth_parser;
    auth_credentials credentials; //aca guardamos user/pass recibidos
    bool auth_success;            //resultado de la validación de credenciales

    request_parser request_parser;

    //Referencia a los usuarios validos
    struct socks5args *args;

    bool close_after_write; // Flag para cerrar después de vaciar el buffer de salida
} client_t;

void socks5_init(client_t *s);

#endif
