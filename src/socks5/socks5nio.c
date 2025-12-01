/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include<stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>

#include <arpa/inet.h>
#include <netdb.h>

#include "hello.h"
#include "request.h"
#include "buffer.h"

#include "stm.h"
#include "socks5nio.h"
#include"netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))




////////////////////////////////////////////////////////////////////
// Definición de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct hello_parser   parser;
    /** el método de autenticación seleccionado */
    uint8_t               method;
};

/** Estado para manejar REQUEST del cliente */
struct request_st {
    buffer *rb, *wb;                // Buffers de lectura/escritura
    struct request_parser parser;   // Parser del mensaje REQUEST
};

/** Estado para el modo COPY (túnel de datos) */
struct copy {
    int fd;          // File descriptor del socket (cliente u origen)
    buffer *rb, *wb; // Buffers de lectura/escritura
};

/** Estado para la conexión asíncrona al servidor origen */
struct connecting {
    buffer *wb;      // Buffer de escritura para la respuesta
};

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una única
 * alocación cuando recibimos la conexión.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {
    /** informacion del cliente */
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    /** informacion del origen */
    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_fd;
    int                           origin_domain;
    struct addrinfo              *origin_resolution;

    /** buffers circulares para I/O no bloqueante */
    buffer read_buffer, write_buffer;

    /** arrays subyacentes para los buffers circulares (2KB cada uno) */
    uint8_t raw_buff_a[2048];
    uint8_t raw_buff_b[2048];

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
        struct copy               copy;
    } orig;

    /** gestión del pool de reutilización de memoria */
    struct socks5 *next;     // Puntero al siguiente en la lista del pool
    unsigned references;     // Contador de referencias (para liberar cuando llega a 0)
};

/** Forward declaration de la tabla de estados (definida más abajo) */
static const struct state_definition client_statbl[];

/** Variables globales para el pool de sesiones:
 * - max_pool: máximo de sesiones a cachear (evita malloc/free excesivo)
 * - pool_size: cantidad actual de sesiones en el pool
 * - pool: lista enlazada de sesiones disponibles para reutilizar
 */
static const unsigned max_pool = 50;
static unsigned pool_size = 0;
static struct socks5 *pool = 0;

/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (socks5 *) desde la llave de selección  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

/**
 * Crea una nueva sesión SOCKS5 para un cliente.
 * Utiliza un pool de objetos para evitar malloc/free frecuentes.
 * 
 * @param client_fd File descriptor del socket del cliente
 * @return Puntero a la sesión inicializada, o NULL si falla
 */
static struct socks5 *
socks5_new(const int client_fd) {
    struct socks5 *ret;
    
    // Intentar reutilizar del pool primero
    if(pool == NULL) {
        ret = malloc(sizeof(*ret));  // Pool vacío, usar malloc
    } else {
        ret = pool;                  // Tomar del pool
        pool = pool->next;           // Avanzar la lista
        ret->next = 0;
        pool_size--;
    }
    
    if(ret == NULL) {
        return ret;  // Fallo de alocación
    }
    
    // Limpiar toda la estructura
    memset(ret, 0x00, sizeof(*ret));
    
    // Inicializar file descriptors
    ret->origin_fd = -1;              // Todavía no conectado al origen
    ret->client_fd = client_fd;       // Socket del cliente
    ret->client_addr_len = sizeof(ret->client_addr);
    
    // Configurar la máquina de estados
    ret->stm.initial = HELLO_READ;    // Primer estado: leer HELLO
    ret->stm.max_state = ERROR;       // Estado máximo (para validación)
    ret->stm.states = client_statbl;  // Tabla de transiciones
    stm_init(&ret->stm);              // Inicializar STM
    
    // Inicializar buffers circulares
    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);
    
    // Vincular buffers al estado inicial (HELLO)
    ret->client.hello.rb = &ret->read_buffer;
    ret->client.hello.wb = &ret->write_buffer;

    // Iniciar con 1 referencia
    ret->references = 1;
    return ret;
}

/** Intenta aceptar la nueva conexión entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5                *state           = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = socks5_new(client);
    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &socks5_handler,
                                              OP_READ, state)) {
        goto fail;
    }
    return ;
fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

////////////////////////////////////////////////////////////////////////////////
// HELLO
////////////////////////////////////////////////////////////////////////////////

/** callback del parser utilizado en `read_hello' */
static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected  = p->data;

    if(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method) {
       *selected = method;
    }
}

/** inicializa las variables de los estados HELLO_… */
static void
hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    d->rb                              = &(ATTACHMENT(key)->read_buffer);
    d->wb                              = &(ATTACHMENT(key)->write_buffer);
    d->parser.data                     = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(
            &d->parser);
}

static unsigned
hello_process(const struct hello_st* d);

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if(hello_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = hello_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** procesamiento del mensaje `hello' */
static unsigned
hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;

    uint8_t m = d->method;
    const uint8_t r = (m == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) ? 0xFF : 0x00;
    if (-1 == hello_marshall(d->wb, r)) {
        ret  = ERROR;
    }
    if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == m) {
        ret  = ERROR;
    }
    return ret;
}

/** 
 * Handler llamado al salir del estado HELLO_READ.
 * Por ahora es un stub vacío (no hay cleanup necesario).
 */
static void hello_read_close(const unsigned state, struct selector_key *key) {
    (void)state;  // Parámetro no usado
    (void)key;    // Parámetro no usado
}

/**
 * Tabla de estados de la máquina de estados.
 * Cada entrada define los handlers para un estado específico.
 * La máquina de estados (stm.c) usa esta tabla para saber qué hacer en cada evento.
 */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,      // Al entrar: inicializar parser
        .on_departure     = hello_read_close,     // Al salir: cleanup (stub por ahora)
        .on_read_ready    = hello_read,           // Cuando hay datos: leer HELLO
    },
    {
        .state            = HELLO_WRITE,
        .on_arrival       = NULL,
        .on_departure     = NULL,
        .on_write_ready   = NULL,  // TODO Phase 1: Implementar escritura de respuesta HELLO
    },
    {
        .state            = DONE,              // Estado terminal: conexión completada
        .on_arrival       = NULL,
        .on_departure     = NULL,
    },
    {
        .state            = ERROR,             // Estado terminal: error ocurrido
        .on_arrival       = NULL,
        .on_departure     = NULL,
    }
};

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
socksv5_done(struct selector_key* key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}
