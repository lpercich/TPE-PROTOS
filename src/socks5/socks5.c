#include "args.h"
#include "parsers/request.h"
#include "selector.h"
#include "stm.h"
#include <errno.h>
#include <hello.h>
#include <socks5.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <server.h>
#include <arpa/inet.h>

static unsigned on_hello_write(struct selector_key *key);
static unsigned on_hello_read(struct selector_key *key);
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_auth_write(struct selector_key *key);
static void on_request(const unsigned state, struct selector_key *key);
static unsigned on_request_read(struct selector_key *key);
static unsigned on_request_write(struct selector_key *key);
static unsigned copy_write(struct selector_key *key);
static unsigned copy_read(struct selector_key *key);

extern const struct fd_handler session_handlers;

static const struct state_definition socks5_states[] = {
    [HELLO_READ] = {.state = HELLO_READ, .on_read_ready = on_hello_read},
    [HELLO_WRITE] =
        {
            .state = HELLO_WRITE,
            .on_write_ready = on_hello_write,
        },
    [AUTH_READ] =
        {
            .state = AUTH_READ,
            .on_read_ready = on_auth_read,
        },
    [AUTH_WRITE] =
        {
            .state = AUTH_WRITE,
            .on_write_ready = on_auth_write,
        },
    [REQUEST_READ] =
        {
            .state = REQUEST_READ,
            .on_arrival = on_request,
            .on_read_ready = on_request_read,
        },
    [REQUEST_WRITE] =
        {
            .state = REQUEST_WRITE,
            .on_write_ready = on_request_write,
        },
    [COPY] =
        {
            .state = COPY,
            .on_read_ready = copy_read,
        },
    [DONE] = {.state = DONE},
    [ERROR] = {.state = ERROR},
};

void socks5_init(client_t *s) {
  s->stm.initial = HELLO_READ;
  s->stm.max_state = ERROR;
  s->stm.states = socks5_states;
  s->stm.current = NULL;
  stm_init(&s->stm);
  // capaz cambiarlo para que no sea loop infinito (?
}

static void on_request(const unsigned state, struct selector_key *key) {
  client_t *s = key->data;
  request_parser_init(&s->request_parser);
  selector_set_interest_key(key, OP_READ);
}

static bool validate_credentials(client_t *s) {
  // Iteramos sobre los usuarios configurados en args
  for (int i = 0; i < MAX_USERS; i++) {
    if (s->args->users[i].name == NULL)
      break; // Fin de la lista

    if (strcmp(s->credentials.username, s->args->users[i].name) == 0 &&
        strcmp(s->credentials.password, s->args->users[i].pass) == 0) {
      return true;
    }
  }
  return false;
}

// HELLO READ: Recibe datos del cliente y alimenta al parser

static unsigned on_hello_read(struct selector_key *key) {
  client_t *session = key->data;
  bool errored = false;

  // Leo del socket al buffer
  size_t nbyte;
  uint8_t *ptr = buffer_write_ptr(&session->read_buffer, &nbyte);
  ssize_t ret = recv(key->fd, ptr, nbyte, 0);

  if (ret <= 0)
    return ERROR; // O hubo un error o se cerro la conexion
  buffer_write_adv(&session->read_buffer, ret);

  // Alimento al parser
  enum hello_state state =
      hello_consume(&session->read_buffer, &session->hello_parser, &errored);
  if (hello_is_done(state, 0)) {
    // termino el handshake - elegimos el método de autenticación
    uint8_t method =
        SOCKS_HELLO_NO_ACCEPTABLE_METHODS; // Por defecto rechazamos

    // Priorizamos autenticación con usuario/contraseña si está disponible
    if (session->hello_parser.supports_userpass) {
      method = SOCKS_HELLO_USERPASS_AUTH;
    } else if (session->hello_parser.supports_no_auth) {
      // Solo aceptamos sin auth si no hay usuarios configurados
      // (o si queremos permitirlo - por ahora lo dejamos)
      method = SOCKS_HELLO_NOAUTHENTICATION_REQUIRED;
    }

    // Guardamos el método elegido para usarlo en hello_write
    session->chosen_method = method;

    // Preparamos la respuesta
    if (-1 == hello_reply(&session->write_buffer, method)) {
      return ERROR;
    }

    return on_hello_write(key);
  }
  if (errored)
    return ERROR;
  return HELLO_READ; // Esperamos los datos
}

// HELLO WRITE: Envio la respuesta al cliente
static unsigned on_hello_write(struct selector_key *key) {
  client_t *session = key->data;
  size_t nbyte;
  uint8_t *ptr = buffer_read_ptr(&session->write_buffer, &nbyte);

  ssize_t ret = send(key->fd, ptr, nbyte, MSG_NOSIGNAL);
  if (ret == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      selector_set_interest(key->s, key->fd, OP_WRITE);
      return HELLO_WRITE;
    }
    return ERROR;
  }
  if (ret == 0)
    return ERROR; // O hubo un error o se cerro la conexion

  buffer_read_adv(&session->write_buffer, ret);

  if (buffer_can_read(&session->write_buffer)) {
    selector_set_interest(key->s, key->fd, OP_WRITE);
    return HELLO_WRITE; // todavia falta mandar datos
  }

  // Ya mandamos todo el saludo - transicionamos según el método elegido
  printf("Handshake completado para el fd %d, método elegido: 0x%02X\n",
         key->fd, session->chosen_method);

  if (session->chosen_method == SOCKS_HELLO_USERPASS_AUTH) {
    // Inicializar el parser de autenticación
    session->auth_parser.creds = &session->credentials;
    auth_parser_init(&session->auth_parser);

    // Cambiar a lectura para recibir credenciales
    selector_set_interest(key->s, key->fd,
                          OP_READ); // aca puse read y decia write, chequear
    return AUTH_READ;
  } else if (session->chosen_method == SOCKS_HELLO_NOAUTHENTICATION_REQUIRED) {
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
  if (ret <= 0)
    return ERROR;
  buffer_write_adv(&s->read_buffer, ret);

  // 2. Parsear
  enum auth_state st = auth_consume(&s->read_buffer, &s->auth_parser, &errored);

  if (auth_is_done(st, &errored)) {
    // 3. Validar Usuario y guardar resultado
    s->auth_success = validate_credentials(s);
    uint8_t status = s->auth_success ? AUTH_SUCCESS : AUTH_FAILURE;

    printf("Auth para fd %d: user='%s' -> %s\n", key->fd,
           s->credentials.username, s->auth_success ? "SUCCESS" : "FAILURE");

    // Preparar respuesta
    if (-1 == auth_marshall(&s->write_buffer, status))
      return ERROR;

    return on_auth_write(key);
  }
  if (errored)
    return ERROR;
  return AUTH_READ;
}

static unsigned on_auth_write(struct selector_key *key) {
  client_t *s = key->data;
  size_t nbyte;
  uint8_t *ptr = buffer_read_ptr(&s->write_buffer, &nbyte);

  ssize_t ret = send(key->fd, ptr, nbyte, MSG_NOSIGNAL);
  if (ret == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      selector_set_interest(key->s, key->fd, OP_WRITE);
      return AUTH_WRITE;
    }
    return ERROR;
  }
  if (ret == 0)
    return ERROR;
  buffer_read_adv(&s->write_buffer, ret);

  if (buffer_can_read(&s->write_buffer)) {
    selector_set_interest(key->s, key->fd, OP_WRITE);
    return AUTH_WRITE;
  }

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

  struct sockaddr_storage *dest_addr = malloc(sizeof(struct sockaddr_storage));
  if(dest_addr == NULL){
    return ERROR; //fallo el malloc
  } 
  memset(dest_addr, 0, sizeof(struct sockaddr_storage));
  // Solo soportamos comando CONNECT (0x01)
  if (p->cmd != 0x01) {
    return ERROR; // O responder 'Command not supported'
  }

  switch (p->atyp)
  {
  case ATYP_IPV4:
    struct sockaddr_in * ip4 = dest_addr;
    ip4->sin_family = AF_INET;
    ip4->sin_port = htons(p->port); //chequear
    ip4->sin_addr.s_addr = p->addr;
    break;

  case ATYP_DOMAIN:
  //TODO: queda pendiente para cuando tengmos la resol de nombres
  break;
  case ATYP_IPV6:
  struct sockaddr_in6 * ip6 = dest_addr;
  break;
  
  default:
  return ERROR;
    break;
  }
  /*
  switch( p->cmd) {
        case SOCKS5_CMD_CONNECT:
            return REQUEST_CONNECT;
        case SOCKS5_CMD_BIND:
            return REQUEST_BIND;
        case SOCKS5_CMD_UDP_ASSOCIATE:
            return REQUEST_UDP_ASSOCIATE;
        default:
            return ERROR;
    }*/

  // --- MOCK DE CONEXIÓN EXITOSA (Para probar el flujo) ---
  // Fingimos que nos conectamos exitosamente al destino

  request_reply reply = {.version = 0x05,
                         .status = 0x00, // Success
                         .bnd.atyp = ATYP_IPV4,
                         .bnd.addr = {0},
                         .bnd.port = 0};

  // Escribimos la respuesta "Falsa" en el buffer de salida
  if (-1 == request_marshall(&s->write_buffer, &reply)) {
    return ERROR;
  }

  // Pasamos a escribir la respuesta al cliente
  return on_request_write(key);
}

static unsigned copy_read(struct selector_key *key) {
  client_t *s = key->data;
  int fd = key->fd;
  bool is_client_fd = (fd == s->client_fd);

  int origin_fd = is_client_fd ? s->origin_fd : s->client_fd; 
  buffer *buffer = is_client_fd ? &s->write_buffer : &s->origin_write_buffer;

  size_t space;

  uint8_t *dst = buffer_write_ptr(buffer, &space);
  ssize_t n = recv(fd, dst, space, 0);

  if (n < 0) {
    perror("COPY recv");
    return ERROR;
  }
  if( n == 0) {
    printf("COPY: El cliente cerró la conexión.\n");
    return DONE;
  }

  buffer_write_adv(buffer, n);

  selector_set_interest(key->s, origin_fd, OP_WRITE);
  selector_set_interest_key(key, buffer_can_write(buffer) ? OP_READ : OP_NOOP);

  return s->stm.current->state;

}

static unsigned copy_write(struct selector_key *key) {
  client_t *s = key->data;
  int fd = key->fd;
  bool is_client_fd = (fd == s->client_fd);

  int origin_fd = is_client_fd ? s->origin_fd : s->client_fd;
  buffer *buffer = is_client_fd ? &s->origin_write_buffer : &s->write_buffer;

  size_t to_send;

  uint8_t *src = buffer_read_ptr(buffer, &to_send);
  ssize_t sent = send(fd, src, to_send, MSG_NOSIGNAL);

  if (sent <= 0) {
    perror("COPY send");
    return ERROR;
  }

  buffer_read_adv(buffer, sent);

  selector_set_interest(key->s, origin_fd, OP_READ);

  unsigned interest = OP_READ;

  if (buffer_can_read(buffer)) {
    interest |= OP_WRITE;
  }

  selector_set_interest_key(key, interest);

  if (is_client_fd && !buffer_can_read(&s->origin_write_buffer) && s->stm.current->state == REQUEST_WRITE) {
    s->stm.current = &s->stm.states[COPY];
    selector_set_interest_key(key, OP_READ);
    selector_register(key->s, s->origin_fd, &session_handlers, OP_READ, s);
    return COPY;
  }

  return s->stm.current->state;
  
}

static unsigned on_request_read(struct selector_key *key) {
  client_t *s = key->data;

  // 1. Escribir en el buffer lo que llega del socket
  size_t wbytes;
  uint8_t *ptr = buffer_write_ptr(&s->read_buffer, &wbytes);
  ssize_t ret = recv(key->fd, ptr, wbytes, 0);

  if (ret < 0) {
    return ERROR; // Error de conexión
  } else if (ret == 0){
    return DONE; //cerro conexion
  }
  buffer_write_adv(&s->read_buffer, ret);

  // 2. Alimentar al parser de Request
  bool errored = false;
  request_state st =
      request_consume(&s->read_buffer, &s->request_parser, &errored);

  if (request_is_done(st, &errored)) {
    // ¡Tenemos el pedido completo! (Ej: CONNECT google.com:80)
    // Procesamos el pedido (ver siguiente función)
    if(!errored){
      return process_request(key);
    } else{
      return ERROR;
    }
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
    request_state rstate = request_consume(&s->read_buffer, &s->request_parser,
&errored); printf("salimos de request_consume\n"); if (errored) {
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
  if (ret == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      selector_set_interest_key(key, OP_WRITE);
      return REQUEST_WRITE;
    }
    return ERROR;
  }
  if (ret == 0)
    return ERROR;

  buffer_read_adv(&s->write_buffer, ret);

  if (buffer_can_read(&s->write_buffer)) {
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE; // Falta enviar
  }

  // Ya le dijimos al cliente "OK, conectado".
  // Ahora pasamos al estado COPY (Túnel).
  // Como aún no tenemos túnel real, usaremos el handler 'on_copy_read'
  // que implementamos antes para leer y descartar (y evitar crash).

  selector_set_interest_key(key, OP_READ);
  return COPY;
}
