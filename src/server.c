#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <stdint.h>

#include "server.h"
#include "lib/buffer.h"
#include "lib/selector.h"
#include "stm.h"
#include "parsers/hello.h"
#include "parsers/auth.h"
#include "args.h"

#define BUFFER_SIZE 4096    

enum socks_v5state {
    HELLO_READ,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    // estados terminales
    DONE,
    ERROR,
};

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

    //Referencia a los usuarios validos
    struct socks5args *args;
} client_t;



static void on_client_read(struct selector_key *key);
static void on_client_write(struct selector_key *key);
static void on_client_close(struct selector_key *key);

static unsigned on_hello_read(struct selector_key *key);
static unsigned on_hello_write(struct selector_key *key);
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_auth_write(struct selector_key *key);

static const struct fd_handler session_handlers = {
    .handle_read  = on_client_read,
    .handle_write = on_client_write,
    .handle_close = on_client_close,
};

static const struct state_definition state_definition[] = {
    {
        .state = HELLO_READ,
        .on_read_ready = on_hello_read,
    },
    {
        .state = HELLO_WRITE,
        .on_write_ready = on_hello_write,
    },
    {
        .state = AUTH_READ,
        .on_read_ready = on_auth_read,
    },
    {
        .state = AUTH_WRITE,
        .on_write_ready = on_auth_write,
    },
    {
        .state = REQUEST_READ,
        // TODO: Implementar on_request_read cuando toque
    },
    {
        .state = DONE,
        // Al llegar a DONE, podríamos cerrar la conexión por ahora
    },
    {
        .state = ERROR,
    }
};

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

static void session_destroy(client_t *session) {
    if (session != NULL) {
        if (session->client_fd >= 0) {
            close(session->client_fd);
        }
        free(session);
    }
}

//crea una nueva session
static client_t *session_new(int fd) {
    client_t *session = malloc(sizeof(client_t));
    if (session == NULL) {
        return NULL;
    }
    memset(session, 0, sizeof(client_t));
    
    session->client_fd = fd;
    session->origin_fd = -1;
    
    // Inicializamos los buffers apuntando a los arrays internos
    buffer_init(&session->read_buffer, BUFFER_SIZE, session->read_memory);
    buffer_init(&session->write_buffer, BUFFER_SIZE, session->write_memory);
    
    session->stm.initial=HELLO_READ;
    session->stm.max_state=ERROR; //quiza cambiarlo para que no me entre en un loop infinito ¿?
    session->stm.states=state_definition;
    session->stm.current = NULL;
    stm_init(&session->stm);

    hello_parser_init(&session->hello_parser);
    session->hello_parser.data = session;

    return session;
}


//Handler de LECTURA: El cliente nos mandó datos.
static void on_client_read(struct selector_key *key) {
    client_t *session = key->data;

    unsigned state = stm_handler_read(&session->stm, key);

    if(state == ERROR || state == DONE) {
        on_client_close(key); //Cerrar si fallo o termino
    }

    /* size_t wbytes;
    
    // 1. Me guarda en el puntero el lugar donde puedo escribir
    uint8_t *write_ptr = buffer_write_ptr(&session->read_buffer, &wbytes);
    
    // 2. Intentamos leer del socket (No bloqueante porque lo llama selector _select() en el main)
    ssize_t n = recv(key->fd, write_ptr, wbytes, 0);
    
    if (n <= 0) {
        // Si n=0 (cierre) o n<0 (error), cerramos la sesión.
        // Al desregistrar, el selector llamará automáticamente a on_client_close.
        selector_unregister_fd(key->s, key->fd);
        return; */
   /*  }
    
    // 3. Confirmamos que leímos 'n' bytes (valida que se haya leido correctamente)
    buffer_write_adv(&session->read_buffer, n);
    
    // --- LÓGICA DE ECO ---
    // Copiamos todo lo que entró en 'input_buffer' hacia 'output_buffer'
    while (buffer_can_read(&session->read_buffer)) {
        // Cuánto hay para leer del input?
        size_t rbytes;
        uint8_t *read_ptr = buffer_read_ptr(&session->read_buffer, &rbytes);
        
        // Cuánto espacio hay en el output?
        size_t available_space;
        uint8_t *out_ptr = buffer_write_ptr(&session->write_buffer, &available_space);
        
        // Copiamos el mínimo entre lo que tengo y lo que entra
        size_t copy_size = (rbytes < available_space) ? rbytes : available_space;
        memcpy(out_ptr, read_ptr, copy_size);
        
        buffer_read_adv(&session->read_buffer, copy_size);
        buffer_write_adv(&session->write_buffer, copy_size);
    }
    
    // 4. Como ahora tenemos datos para enviar, nos interesa el evento WRITE
    selector_set_interest(key->s, key->fd, OP_WRITE); */
}


//Handler de ESCRITURA: El socket está listo para enviar datos.
static void on_client_write(struct selector_key *key) {
    client_t *session = key->data;
    unsigned state = stm_handler_write(&session->stm, key);
    
    if(state == ERROR || state == DONE) {
        selector_unregister_fd(key->s, key->fd);
    }
   /*  size_t rbytes;
    
    // 1. ¿Qué tengo para mandar?
    uint8_t *read_ptr = buffer_read_ptr(&session->write_buffer, &rbytes);
    
    // 2. Intentamos enviar
    ssize_t n = send(key->fd, read_ptr, rbytes, MSG_NOSIGNAL);
    
    if (n == -1) {
        selector_unregister_fd(key->s, key->fd);
        return;
    }
    
    // 3. Confirmamos que enviamos 'n' bytes (avanzamos el puntero de lectura)
    buffer_read_adv(&session->write_buffer, n);
    
    // 4. Si ya no queda nada en el buffer de salida, volvemos a solo leer
    if (!buffer_can_read(&session->write_buffer)) {
        selector_set_interest(key->s, key->fd, OP_READ);
    } */
}

//Handler de CIERRE: El socket se cerró.
static void on_client_close(struct selector_key *key) {
    client_t *session = key->data;
    printf("Cerrando conexión en fd %d\n", key->fd);
    session_destroy(session);
}


//Handler PÚBLICO: Acepta nuevas conexiones SOCKS5.
void socksv5_passive_accept(struct selector_key *key) {
    struct socks5args *args = key->data;  // Obtenemos la configuración del servidor
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    
    // 1. Aceptar conexión entrante
    int new_fd = accept(key->fd, (struct sockaddr*)&client_addr, &client_addr_len);
    if (new_fd < 0) {
        // Error temporal o fatal, por ahora solo logueamos
        perror("accept()");
        return;
    }
    
    // 2. Configurar NO BLOQUEANTE (Fundamental)
    if (selector_fd_set_nio(new_fd) == -1) {
        perror("selector_fd_set_nio()");
        close(new_fd);
        return;
    }
    
    // 3. Crear estado para este nuevo cliente
    client_t *new_session = session_new(new_fd);
    if (new_session == NULL) {
        // Sin memoria
        close(new_fd);
        return;
    }
    
    // Vincular la configuración (usuarios para autenticación)
    new_session->args = args;
    
    // 4. Registrar en el selector
    // Nos interesa leer (OP_READ) inicialmente
    selector_status ss = selector_register(key->s, new_fd, &session_handlers, OP_READ, new_session);
    
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "Error registrando cliente en selector: %s\n", selector_error(ss));
        session_destroy(new_session); // Esto cierra el fd y libera memoria
        return;
    }
    
    printf("Nueva conexión aceptada en fd %d\n", new_fd);
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

//AGREGO FUNCIONES PARA IR VIENDO ACCIONES CON STM

//CHEQUEAR EN TODAS las funcs SOCKS: deberia actualizar el estado con el ret de la funcion se stm????
//lectura para socks5
static void socks5_client_read(struct selector_key *key) {
client_t * session= key->data;
stm_handler_read(&session->stm, key); 
}

//escritura para socks
static void socks5_client_write(struct selector_key *key) {
client_t * session= key->data;
stm_handler_write(&session->stm, key); 
}

static void socks5_client_block (struct selector_key *key){
    client_t * session= key->data;
    stm_handler_block(&session->stm, key);
}

static void socks5_client_close (struct selector_key *key){
     client_t * session= key->data;
    stm_handler_close(&session->stm, key);
}