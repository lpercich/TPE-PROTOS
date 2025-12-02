#include <socks5.h>
#include <hello.h>
#include "stm.h"
#include "selector.h"
#include "parsers/request.h"
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include "args.h"
#include <errno.h>

static unsigned on_hello_write(struct selector_key *key);
static unsigned on_hello_read(struct selector_key *key);
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_auth_write(struct selector_key *key);
static void on_request(const unsigned state, struct selector_key *key);
static unsigned on_request_read(struct selector_key *key);
static unsigned on_request_write(struct selector_key *key);

static unsigned copy_read(struct selector_key *key) {
    client_t *s = key->data;
    
    // Usamos un buffer temporal para sacar los datos del socket
    // (No usamos s->read_buffer para no ensuciarlo por ahora)
    uint8_t buf[1024];
    ssize_t n = recv(key->fd, buf, sizeof(buf), 0);
    
    if (n > 0) {
        // ¡Llegaron datos! Esto es lo que curl le mandó a Google
        // Como agregaste un '\0' al final podrías imprimirlo como string
        buf[n] = 0; 
        printf("COPY (Dummy): Recibí %zd bytes: %s\n", n, (char*)buf);
        
        // MANTENER VIVA: Retornamos COPY para seguir en este estado
        // esperando más datos o que el otro lado responda.
        return COPY; 
    } 
    
    if (n == 0) {
        printf("COPY: El cliente cerró la conexión.\n");
        return DONE; // Recién acá cerramos nosotros
    }

    if (n < 0) {
        // Si es error de bloqueo, seguimos esperando
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return COPY;
        }
        perror("COPY recv");
        return ERROR;
    }
    return COPY;
}

static const struct state_definition socks5_states[] = {
    [HELLO_READ] = {
        .state = HELLO_READ, 
        .on_read_ready  =  on_hello_read
    },
    [HELLO_WRITE] = {
        .state = HELLO_WRITE,
        .on_write_ready = on_hello_write,
    },
    [AUTH_READ]    = { 
        .state = AUTH_READ,
        .on_read_ready  = on_auth_read,
    },
    [AUTH_WRITE]   = { 
        .state = AUTH_WRITE,
        .on_write_ready = on_auth_write,
    },
    [REQUEST_READ] = { 
        .state = REQUEST_READ,
        .on_arrival = on_request,
        .on_read_ready  = on_request_read,
    },
    [REQUEST_WRITE]= { 
        .state = REQUEST_WRITE,
        .on_write_ready = on_request_write,
    },
    [COPY]         = { 
        .state = COPY,
        .on_read_ready  = copy_read,
    },
    [DONE]         = { 
        .state = DONE 
    },
    [ERROR]        = { 
        .state = ERROR 
    },
};

void socks5_init(client_t *s) {
    s->stm.initial = HELLO_READ;
    s->stm.max_state = ERROR;
    s->stm.states = socks5_states;
    s->stm.current = NULL;
    stm_init(&s->stm);
    //capaz cambiarlo para que no sea loop infinito (?
}

static void on_request(const unsigned state, struct selector_key *key) {
    selector_set_interest_key(key, OP_READ);
}

static bool validate_credentials(client_t *s) {
    // Iteramos sobre los usuarios configurados en args
    for (int i = 0; i < MAX_USERS; i++) {
        if (s->args->users[i].name == NULL) break; // Fin de la lista
        
        if (strcmp(s->credentials.username, s->args->users[i].name) == 0 &&
            strcmp(s->credentials.password, s->args->users[i].pass) == 0) {
            return true;
        }
    }
    return false;
}


//HELLO READ: Recibe datos del cliente y alimenta al parser

static unsigned on_hello_read(struct selector_key *key) {
    client_t *session = key->data;
    bool errored = false;

    //Leo del socket al buffer
    size_t nbyte;
    uint8_t *ptr = buffer_write_ptr(&session->read_buffer, &nbyte);
    ssize_t ret = recv(key->fd, ptr, nbyte, 0);
    
    if(ret <= 0) return ERROR; //O hubo un error o se cerro la conexion
    buffer_write_adv(&session->read_buffer, ret);
    
    //Alimento al parser
    enum hello_state state = hello_consume(&session->read_buffer, &session->hello_parser, &errored);
    if(hello_is_done(state, 0)) {
        //termino el handshake - elegimos el método de autenticación
        uint8_t method = SOCKS_HELLO_NO_ACCEPTABLE_METHODS; // Por defecto rechazamos
        
        // Priorizamos autenticación con usuario/contraseña si está disponible
        if(session->hello_parser.supports_userpass) {
            method = SOCKS_HELLO_USERPASS_AUTH;
        } else if(session->hello_parser.supports_no_auth) {
            // Solo aceptamos sin auth si no hay usuarios configurados
            // (o si queremos permitirlo - por ahora lo dejamos)
            method = SOCKS_HELLO_NOAUTHENTICATION_REQUIRED;
        }
        
        // Guardamos el método elegido para usarlo en hello_write
        session->chosen_method = method;
        
        // Preparamos la respuesta
        if(-1 == hello_reply(&session->write_buffer, method)) {
            return ERROR;
        }

        //Cambio de interes a WRITE asi mando la rta
        selector_set_interest(key->s, key->fd, OP_WRITE);
        return HELLO_WRITE;
    }
    if(errored) return ERROR;
    return HELLO_READ; //Esperamos los datos
}

//HELLO WRITE: Envio la respuesta al cliente
static unsigned on_hello_write(struct selector_key *key) {
    client_t *session = key->data;
    size_t nbyte;
    uint8_t *ptr = buffer_read_ptr(&session->write_buffer, &nbyte);
    
    ssize_t ret = send(key->fd, ptr, nbyte, MSG_NOSIGNAL);
    if(ret <= 0) return ERROR; //O hubo un error o se cerro la conexion
    
    buffer_read_adv(&session->write_buffer, ret);
    
    if(buffer_can_read(&session->write_buffer)) {
        return HELLO_WRITE; //todavia falta mandar datos
    }
    
    // Ya mandamos todo el saludo - transicionamos según el método elegido
    printf("Handshake completado para el fd %d, método elegido: 0x%02X\n", key->fd, session->chosen_method);

    if(session->chosen_method == SOCKS_HELLO_USERPASS_AUTH) {
        // Inicializar el parser de autenticación
        session->auth_parser.creds = &session->credentials;
        auth_parser_init(&session->auth_parser);
        
        // Cambiar a lectura para recibir credenciales
        selector_set_interest(key->s, key->fd, OP_READ); // aca puse read y decia write, chequear
        return AUTH_READ;
    } else if(session->chosen_method == SOCKS_HELLO_NOAUTHENTICATION_REQUIRED) {
        // Sin autenticación, pasamos directo a REQUEST
        selector_set_interest(key->s, key->fd, OP_READ);
        return REQUEST_READ;
    } else {
        // 0xFF o método no soportado - cerramos conexión
        return ERROR;
    }
}

static unsigned on_auth_read(struct selector_key *key) {
    client_t *s = key->data;
    bool errored = false;

    // 1. Leer del socket
    size_t nbyte;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &nbyte);
    ssize_t ret = recv(key->fd, ptr, nbyte, 0);
    if (ret <= 0) return ERROR;
    buffer_write_adv(&s->read_buffer, ret);

    // 2. Parsear
    enum auth_state st = auth_consume(&s->read_buffer, &s->auth_parser, &errored);

    if (auth_is_done(st, &errored)) {
        // 3. Validar Usuario y guardar resultado
        s->auth_success = validate_credentials(s);
        uint8_t status = s->auth_success ? AUTH_SUCCESS : AUTH_FAILURE;
        
        printf("Auth para fd %d: user='%s' -> %s\n", 
               key->fd, s->credentials.username, 
               s->auth_success ? "SUCCESS" : "FAILURE");
        
        // Preparar respuesta
        if (-1 == auth_marshall(&s->write_buffer, status)) return ERROR;
        
        selector_set_interest(key->s, key->fd, OP_WRITE);
        return AUTH_WRITE;
    }
    if (errored) return ERROR;
    return AUTH_READ;
}

static unsigned on_auth_write(struct selector_key *key) {
    client_t *s = key->data;
    size_t nbyte;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &nbyte);
    
    ssize_t ret = send(key->fd, ptr, nbyte, MSG_NOSIGNAL);
    if (ret <= 0) return ERROR;
    buffer_read_adv(&s->write_buffer, ret);

    if (buffer_can_read(&s->write_buffer)) return AUTH_WRITE;

    // Usamos el resultado guardado en on_auth_read
    if (s->auth_success) {
        printf("Auth exitosa, pasando a REQUEST_READ para fd %d\n", key->fd);
        selector_set_interest(key->s, key->fd, OP_READ);
        return REQUEST_READ;
    } else {
        printf("Auth fallida, cerrando conexión fd %d\n", key->fd);
        return ERROR; // Auth fallida = cerrar conexión
    }
}

static unsigned process_request(struct selector_key *key) {
    client_t *s = key->data;
    request_parser *p = &s->request_parser;

    printf("Request recibido: CMD=%d, ATYP=%d\n", p->cmd, p->atyp);

    // Solo soportamos comando CONNECT (0x01)
    if (p->cmd != 0x01) {
        return ERROR; // O responder 'Command not supported'
    }

    // --- MOCK DE CONEXIÓN EXITOSA (Para probar el flujo) ---
    // Fingimos que nos conectamos exitosamente al destino
    
    request_reply reply = {
        .version = 0x05,
        .status = 0x00, // Success
        .bnd.atyp = ATYP_IPV4,
        .bnd.addr = {0},
        .bnd.port = 0
    };
    
    // Escribimos la respuesta "Falsa" en el buffer de salida
    if (-1 == request_marshall(&s->write_buffer, &reply)) {
        return ERROR;
    }
    
    // Pasamos a escribir la respuesta al cliente
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
}

static unsigned on_request_read(struct selector_key *key) {
    client_t *s = key->data;
    
    // 1. Escribir en el buffer lo que llega del socket
    size_t wbytes;
    uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &wbytes);
    ssize_t ret = recv(key->fd, ptr, wbytes, 0);

    if (ret <= 0) {
        return ERROR; // Cierre o error de conexión
    }
    buffer_write_adv(&s->read_buffer, ret);

    // 2. Alimentar al parser de Request
    bool errored = false;
    request_state st = request_consume(&s->read_buffer, &s->request_parser, &errored);

    if (request_is_done(st, &errored)) {
        // ¡Tenemos el pedido completo! (Ej: CONNECT google.com:80)
        // Procesamos el pedido (ver siguiente función)
        return process_request(key);
    }

    if (errored) {
        // TODO: Aquí deberíamos responder error 0x01 antes de cerrar
        return ERROR;
    }

    return REQUEST_READ; // Faltan datos, seguimos esperando
}

/* static unsigned on_request_read(struct selector_key *key) {
    printf("Adentro de on_request_read\n");
    client_t *s = key->data;
    bool errored = false;

    // 1) Leer del socket
    size_t space;
    uint8_t *dst = buffer_write_ptr(&s->read_buffer, &space);
    ssize_t ret = recv(key->fd, dst, space, 0);
    if (ret <= 0) return ERROR;
    buffer_write_adv(&s->read_buffer, ret);
    // 2) Parsear el mensaje 
    request_state rstate = request_consume(&s->read_buffer, &s->request_parser, &errored);
    printf("salimos de request_consume\n");
    if (errored) {
        printf("errored\n");
        return ERROR;
    }

    // 3) Terminó la request?
    if (request_is_done(rstate, &errored)) {
        printf("entre al if de request is done\n");
        // Por ahora solo soportamos CONNECT. (TODO los otros commandos)
        if (s->request_parser.cmd != 0x01) {
            return ERROR;    
        }

        // 4) Construyo el reply 
        request_reply reply;
        memset(&reply, 0, sizeof(reply));

        reply.version = SOCKS5_VERSION;
        reply.status  = 0x00;    // éxito
        reply.bnd.atyp = ATYP_IPV4;
        reply.bnd.port = 0;      // 0.0.0.0:0 (sin origen real todavía)
        memset(reply.bnd.addr, 0, 4);

        if (request_marshall(&s->write_buffer, &reply) < 0) {
            return ERROR;
        }

        // 5) Escribimos
        selector_set_interest(key->s, key->fd, OP_WRITE);
        return REQUEST_WRITE;
    }

    //Todavía falta recibir bytes
    return REQUEST_READ;
}
 */
/* static unsigned on_request_write(struct selector_key *key) {
    client_t *s = key->data;

    //1) Qué hay para mandar?
    size_t nbytes;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &nbytes);

    if (nbytes == 0) {
        return ERROR;   // no debería pasar
    }

    //  2) Enviar
    ssize_t n = send(key->fd, ptr, nbytes, MSG_NOSIGNAL);
    if (n <= 0) {
        return ERROR;
    }

    buffer_read_adv(&s->write_buffer, n);

    // 3) Queda por enviar?
    if (buffer_can_read(&s->write_buffer)) {
        return REQUEST_WRITE;
    }

    // 4) pasamos a COPY 
    selector_set_interest(key->s, key->fd, OP_READ);
    return COPY;
}
 */

 static unsigned on_request_write(struct selector_key *key) {
    client_t *s = key->data;
    size_t nbyte;
    uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &nbyte);
    
    ssize_t ret = send(key->fd, ptr, nbyte, MSG_NOSIGNAL);
    if (ret <= 0) return ERROR;
    
    buffer_read_adv(&s->write_buffer, ret);
    
    if (buffer_can_read(&s->write_buffer)) {
        return REQUEST_WRITE; // Falta enviar
    }
    
    // Ya le dijimos al cliente "OK, conectado".
    // Ahora pasamos al estado COPY (Túnel).
    // Como aún no tenemos túnel real, usaremos el handler 'on_copy_read'
    // que implementamos antes para leer y descartar (y evitar crash).
    
    selector_set_interest_key(key, OP_READ);
    return COPY;
}
