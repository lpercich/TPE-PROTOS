#include <socks5.h>
#include <hello.h>
#include "stm.h"
#include "selector.h"
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include "args.h"

static unsigned on_hello_write(struct selector_key *key);
static unsigned on_hello_read(struct selector_key *key);
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_auth_write(struct selector_key *key);

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
    },
    [REQUEST_WRITE]= { 
        .state = REQUEST_WRITE,
    },
    [COPY]         = { 
        .state = COPY,
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
    printf("Handshake completado para el fd %d, método elegido: 0x%02X\n", 
           key->fd, session->chosen_method);
    
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

