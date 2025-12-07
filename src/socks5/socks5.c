#include "args.h"
#include "dns.h"
#include "lib/netutils.h"
#include "management/logger.h"
#include "management/metrics.h"
#include "management/mng_users.h"
#include "parsers/request.h"
#include "selector.h"
#include "stm.h"
#include <arpa/inet.h>
#include <errno.h>
#include <hello.h>
#include <netdb.h>
#include <server.h>
#include <socks5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static unsigned on_hello_write(struct selector_key *key);
static unsigned on_hello_read(struct selector_key *key);
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_auth_write(struct selector_key *key);
static void on_request(const unsigned state, struct selector_key *key);
static unsigned on_request_read(struct selector_key *key);
static unsigned on_request_write(struct selector_key *key);
static unsigned copy_write(struct selector_key *key);
static unsigned copy_read(struct selector_key *key);
static unsigned request_connect_init(const unsigned state,
                                     struct selector_key *key);
static unsigned request_connect_done(struct selector_key *key);
static unsigned on_request_resolve(struct selector_key *key);
static unsigned on_request_bind(struct selector_key *key);

static void socks5_client_read(struct selector_key *key);
static void socks5_client_write(struct selector_key *key);
static void socks5_client_close(struct selector_key *key);
static void socks5_client_block(struct selector_key *key);
static int get_bound_addr(int fd, reply_addr_t *addr);
int build_reply(const request_reply *r, uint8_t **out_buf, size_t *out_len);

extern const struct fd_handler *get_session_handler();

extern const struct fd_handler session_handlers;

static const struct fd_handler socks5_handler = {
    .handle_read = socks5_client_read,
    .handle_write = socks5_client_write,
    .handle_close = socks5_client_close,
    .handle_block = socks5_client_block,
};

static const struct state_definition socks5_states[] = {
    [HELLO_READ] = {.state = HELLO_READ, .on_read_ready = on_hello_read},
    [HELLO_WRITE] = {.state = HELLO_WRITE, .on_write_ready = on_hello_write},
    [AUTH_READ] = {.state = AUTH_READ, .on_read_ready = on_auth_read},
    [AUTH_WRITE] = {.state = AUTH_WRITE, .on_write_ready = on_auth_write},
    [REQUEST_READ] = {.state = REQUEST_READ,
                      .on_arrival = on_request,
                      .on_read_ready = on_request_read},
    [REQUEST_WRITE] = {.state = REQUEST_WRITE,
                       .on_write_ready = on_request_write},
    [COPY] = {.state = COPY,
              .on_read_ready = copy_read,
              .on_write_ready = copy_write},
    [REQUEST_CONNECT] = {.state = REQUEST_CONNECT,
                         .on_arrival = NULL,
                         .on_write_ready = request_connect_done},
    [REQUEST_RESOLVE] = {.state = REQUEST_RESOLVE,
                         .on_block_ready = on_request_resolve},
    [REQUEST_BIND] = {.state = REQUEST_BIND, .on_write_ready = on_request_bind},
    [DONE] = {.state = DONE},
    [ERROR] = {.state = ERROR},
};

void socks5_init(client_t *s) {
  s->stm.initial = HELLO_READ;
  s->stm.max_state = ERROR;
  s->stm.states = socks5_states;
  s->stm.current = NULL;
  stm_init(&s->stm);
}

static void on_request(const unsigned state, struct selector_key *key) {
  client_t *s = key->data;
  request_parser_init(&s->request_parser);
  selector_set_interest_key(key, OP_READ);
}

static bool validate_credentials(client_t *s) {
  return check_credentials(s->credentials.username, s->credentials.password);
}

// HELLO READ: Recibe datos del cliente y alimenta al parser

static unsigned on_hello_read(struct selector_key *key) {
  client_t *session = key->data;
  bool errored = false;

  // Leo del socket al buffer
  size_t nbyte;
  uint8_t *ptr = buffer_write_ptr(&session->read_buffer, &nbyte);
  ssize_t ret = recv(key->fd, ptr, nbyte, 0);

  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return HELLO_READ;
    }
    return ERROR;
  }
  if (ret == 0) {
    return ERROR;
  }
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
  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return AUTH_READ;
    }
    return ERROR;
  }
  if (ret == 0) {
    return ERROR;
  }
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
    printf("Auth exitosa, pasando a REQUEST_READ para fd %d (user= %s)\n", key->fd, s->credentials.username);
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

  // 1. Validar comando (Solo soportamos CONNECT 0x01)
  if (p->cmd != 0x01) {
    // return request_write_error(key, 0x07); // Command not supported
    return ERROR;
  }

  // 2. Preparar la dirección en la estructura persistente
  s->origin_domain = AF_INET;
  memset(&s->origin_addr, 0, sizeof(s->origin_addr));

  switch (p->atyp) {
  case ATYP_IPV4: {
    s->origin_domain = AF_INET;
    s->origin_addr_len = sizeof(struct sockaddr_in);

    struct sockaddr_in *ip4 = (struct sockaddr_in *)&s->origin_addr;
    ip4->sin_family = AF_INET;
    ip4->sin_port = htons(p->port);
    // Copiamos los 4 bytes del array al struct
    memcpy(&ip4->sin_addr, p->addr, 4);
    break;
  }

  case ATYP_IPV6: {
    s->origin_domain = AF_INET6;
    s->origin_addr_len = sizeof(struct sockaddr_in6);

    struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)&s->origin_addr;
    ip6->sin6_family = AF_INET6;
    ip6->sin6_port = htons(p->port);
    // Copiamos los 16 bytes del array al struct
    memcpy(&ip6->sin6_addr, p->addr, 16);
    break;
  }

  case ATYP_DOMAIN: {
    struct selector_key *k = malloc(sizeof(*k));
    *k = *key;

    pthread_t tid;
    pthread_create(&tid, NULL, dns_resolve, k);
    pthread_detach(tid);

    selector_set_interest(key->s, key->fd, OP_NOOP);
    return REQUEST_RESOLVE;
  }

  default:
    return ERROR; // Tipo no soportado
  }

  s->origin_fd = socket(s->origin_domain, SOCK_STREAM, 0);
  if (s->origin_fd == -1) {
    return ERROR; // O request_write_error(key, 0x01);
  }

  if (selector_fd_set_nio(s->origin_fd) == -1) {
    close(s->origin_fd);
    return ERROR;
  }

  int ret = connect(s->origin_fd, (struct sockaddr *)&s->origin_addr,
                    s->origin_addr_len);

  if (ret == -1) {
    if (errno == EINPROGRESS) {
      // Conexión en curso: Registramos el origen en el selector
      // IMPORTANTE: Usamos el mismo handler que en init_connection_to_origin
      selector_status ss = selector_register(
          key->s, s->origin_fd, get_session_handler(), OP_WRITE, s);
      if (ss != SELECTOR_SUCCESS) {
        close(s->origin_fd);
        return ERROR;
      }
      s->references++; // Incrementamos referencias porque ahora hay dos FDs
                       // apuntando a s
      // Pausamos lectura del cliente
      selector_set_interest_key(key, OP_NOOP);

      return REQUEST_CONNECT; // Vamos a esperar a que conecte
    }

    // Falló connect inmediato - enviar error apropiado
    int saved_errno = errno;
    close(s->origin_fd);
    s->origin_fd = -1;

    // Preparar respuesta de error
    request_reply reply = {
        .version = SOCKS5_VERSION,
        .status = (saved_errno == ENETUNREACH || saved_errno == EHOSTUNREACH)
                      ? 0x04
                      : 0x01, // 0x04 = Host unreachable, 0x01 = General failure
        .bnd.atyp = ATYP_IPV4,
        .bnd.addr = {0},
        .bnd.port = 0};

    if (-1 == request_marshall(&s->write_buffer, &reply)) {
      return ERROR;
    }

    s->close_after_write = true;
    selector_set_interest_key(key, OP_WRITE);
    return REQUEST_WRITE;
  }

  // Conectó inmediato (raro) -> Llamar a success directo o ir a estado
  // intermedio
  return REQUEST_CONNECT; // Dejamos que el selector nos avise WRITE igual para
                          // simplificar
}

static void log_connection(client_t *s, const char *status) {
  char src_addr[64], dst_addr[64];
  struct sockaddr_storage client_addr;
  socklen_t len = sizeof(client_addr);

  if (getpeername(s->client_fd, (struct sockaddr *)&client_addr, &len) == 0) {
    sockaddr_to_human(src_addr, sizeof(src_addr),
                      (struct sockaddr *)&client_addr);
  } else {
    strncpy(src_addr, "unknown", sizeof(src_addr));
  }

  sockaddr_to_human(dst_addr, sizeof(dst_addr),
                    (struct sockaddr *)&s->origin_addr);
  log_access(s->credentials.username, src_addr, dst_addr, status);
}

static unsigned request_connect_success(struct selector_key *key) {
  client_t *s = key->data;

  // 1. Armar respuesta OK (Esto está bien)
  request_reply reply = {.version = SOCKS5_VERSION,
                         .status = 0x00,
                         .bnd.atyp = ATYP_IPV4,
                         .bnd.addr = {0},
                         .bnd.port = 0};

  if (-1 == request_marshall(&s->write_buffer, &reply))
    return ERROR;

  // Log successful connection
  log_connection(s, "CONNECT");

  // 2. Configurar intereses COPY
  // IMPORTANTE: Activamos OP_WRITE en el CLIENTE para que el selector
  // llame a 'on_request_write' con la key correcta en el próximo ciclo.
  selector_set_interest(key->s, s->client_fd, OP_WRITE);

  // Escuchamos al origen (Google) por si manda datos
  selector_set_interest(key->s, s->origin_fd, OP_READ);

  // 3. Setup punteros COPY
  s->buf_client_to_origin = &s->read_buffer;
  s->buf_origin_to_client = &s->write_buffer;

  // Transicionamos al estado de escritura.
  // El selector se encargará de ejecutar on_request_write sobre client_fd.
  return REQUEST_WRITE;
}

static unsigned request_connect_done(struct selector_key *key) {
  client_t *s = key->data;
  int error = 0;
  socklen_t len = sizeof(error);

  // Chequeamos si conectó
  if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    error = errno;

  if (error == 0) {
    return request_connect_success(key);
  } else {
    // Falló: enviar error apropiado al cliente
    selector_unregister_fd(key->s, s->origin_fd);
    close(s->origin_fd);
    s->origin_fd = -1;

    // Preparar respuesta de error
    request_reply reply = {
        .version = SOCKS5_VERSION,
        .status = (error == ENETUNREACH || error == EHOSTUNREACH) ? 0x04 : 0x01,
        .bnd.atyp = ATYP_IPV4,
        .bnd.addr = {0},
        .bnd.port = 0};

    if (-1 == request_marshall(&s->write_buffer, &reply)) {
      return ERROR;
    }

    s->close_after_write = true;
    selector_set_interest(key->s, s->client_fd, OP_WRITE);
    return REQUEST_WRITE;
  }
}

static size_t current_buffer_size = BUFFER_SIZE;

void configure_buffer_size(size_t size) {
  if (size > 0 && size <= BUFFER_SIZE) {
    current_buffer_size = size;
  }
}

static unsigned copy_read(struct selector_key *key) {
  client_t *s = key->data;
  int fd = key->fd;
  bool is_client_fd = (fd == s->client_fd);

  int origin_fd = is_client_fd ? s->origin_fd : s->client_fd;
  // Si leo del cliente, escribo en el buffer que lee el origen (read_buffer)
  // Si leo del origen, escribo en el buffer que lee el cliente (write_buffer)
  buffer *buffer = is_client_fd ? &s->read_buffer : &s->write_buffer;

  size_t space;

  uint8_t *dst = buffer_write_ptr(buffer, &space);
  // limitar read size a current_buffer_size
  if (space > current_buffer_size) {
    space = current_buffer_size;
  }
  ssize_t n = recv(fd, dst, space, 0);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return s->stm.current->state;
    }
    perror("COPY recv");
    return ERROR;
  }
  if (n == 0) {
    if (key->fd == s->client_fd) {
      printf("COPY: El CLIENTE cerró la conexión.\n");
    } else {
      printf("COPY: El ORIGEN cerró la conexión.\n");
    }

    s->close_after_write = true;
    return DONE;
  }

  buffer_write_adv(buffer, n);
  transfer_bytes(n);

  selector_set_interest(key->s, origin_fd, OP_WRITE);
  selector_set_interest_key(key, buffer_can_write(buffer) ? OP_READ : OP_NOOP);

  return s->stm.current->state;
}

static unsigned copy_write(struct selector_key *key) {
  client_t *s = key->data;
  int fd = key->fd;
  bool is_client_fd = (fd == s->client_fd);

  int origin_fd = is_client_fd ? s->origin_fd : s->client_fd;
  // Si escribo al cliente, leo del buffer donde escribe el origen
  // (write_buffer) Si escribo al origen, leo del buffer donde escribe el
  // cliente (read_buffer)
  buffer *buffer = is_client_fd ? &s->write_buffer : &s->read_buffer;

  size_t to_send;

  uint8_t *src = buffer_read_ptr(buffer, &to_send);
  ssize_t sent = send(fd, src, to_send, MSG_NOSIGNAL);

  if (sent <= 0) {
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return s->stm.current->state;
    }
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

  if (is_client_fd && !buffer_can_read(&s->write_buffer) &&
      s->stm.current->state == REQUEST_WRITE) {
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
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return REQUEST_READ;
    }
    return ERROR; // Error de conexión
  } else if (ret == 0) {
    return DONE; // cerro conexion
  }
  buffer_write_adv(&s->read_buffer, ret);

  // 2. Alimentar al parser de Request
  bool errored = false;
  request_state st =
      request_consume(&s->read_buffer, &s->request_parser, &errored);

  if (request_is_done(st, &errored)) {
    // ¡Tenemos el pedido completo! (Ej: CONNECT google.com:80)
    // Procesamos el pedido (ver siguiente función)
    if (!errored) {
      return process_request(key);
    } else {
      return ERROR;
    }
  }

  if (errored) {
    // TODO: Aquí deberíamos responder error 0x01 antes de cerrar
    return ERROR;
  }

  return REQUEST_READ; // Faltan datos, seguimos esperando
}

static unsigned init_connection_to_origin(client_t *s,
                                          struct selector_key *key) {
  int fd = socket(s->origin_domain, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return ERROR;
  }

  // No bloqueante
  if (selector_fd_set_nio(fd) == -1) {
    close(fd);
    return ERROR;
  }

  s->origin_fd = fd;

  int ret = connect(fd, (struct sockaddr *)&s->origin_addr, s->origin_addr_len);
  if (ret < 0 && errno != EINPROGRESS) {
    close(fd);
    s->origin_fd = -1;
    return ERROR;
  }

  // Esperamos a que conecte
  selector_status ss =
      selector_register(key->s, fd, get_session_handler(), OP_WRITE, s);
  if (ss != SELECTOR_SUCCESS) {
    close(fd);
    s->origin_fd = -1;
    return ERROR;
  }
  s->references++;

  return REQUEST_CONNECT;
}

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

  // Si habíamos marcado que esto era un error fatal (ej: Auth fallida o Comando
  // inválido), cerramos.
  if (s->close_after_write) {
    return ERROR; // El selector cerrará el socket
  }

  // Ya le dijimos al cliente "OK, conectado".
  // Ahora pasamos al estado COPY (Túnel).
  // Como aún no tenemos túnel real, usaremos el handler 'on_copy_read'
  // que implementamos antes para leer y descartar (y evitar crash).

  selector_set_interest_key(key, OP_READ);
  // Verificar si quedaron datos del cliente pendientes de envío al origen
  if (s->origin_fd != -1) {
    if (buffer_can_read(s->buf_client_to_origin)) {
      // Si hay datos remanentes (el GET), activamos escritura en el origen
      selector_set_interest(key->s, s->origin_fd, OP_WRITE | OP_READ);
    } else {
      // Si está vacío, solo escuchamos
      selector_set_interest(key->s, s->origin_fd, OP_READ);
    }
  }

  return COPY;
}

static unsigned on_request_resolve(struct selector_key *key) {
  client_t *s = key->data;

  struct addrinfo *res = s->res_addr;
  struct addrinfo *p = res;

  if (p == NULL) {
    // host unreachable
    printf("DNS: dominio no resuelto.\n");

    request_reply rep = {
        .version = SOCKS5_VERSION,
        .status = 0x04, // host unreachable
        .bnd.atyp = ATYP_IPV4,
        .bnd.port = 0,
    };
    memset(rep.bnd.addr, 0, 4);

    if (-1 == request_marshall(&s->write_buffer, &rep)) {
      return ERROR;
    }

    selector_set_interest(key->s, key->fd, OP_WRITE);
    return REQUEST_WRITE;
  }

  // Tomamos el primer resultado válido
  s->current_res = p;

  // Copiar dirección resuelta a s->origin_addr
  memcpy(&s->origin_addr, p->ai_addr, p->ai_addrlen);
  s->origin_addr_len = p->ai_addrlen;
  s->origin_domain = p->ai_family;

  // Liberar lista completa
  freeaddrinfo(res);
  s->res_addr = NULL;

  // Ahora conectar
  return init_connection_to_origin(s, key);
}

static void socks5_client_read(struct selector_key *key) {
  client_t *session = key->data;
  // Guardamos el estado al que transicionó
  unsigned state = stm_handler_read(&session->stm, key);

  // Si terminamos o hubo error, cerramos todo
  if (state == DONE || state == ERROR) {
    int other_fd = -1;
    if (key->fd == session->client_fd) {
      other_fd = session->origin_fd;
    } else if (key->fd == session->origin_fd) {
      other_fd = session->client_fd;
    }

    selector_unregister_fd(key->s, key->fd);

    if (other_fd >= 0) {
      selector_unregister_fd(key->s, other_fd);
    }
  }
}

static void socks5_client_write(struct selector_key *key) {
  client_t *session = key->data;
  unsigned state = stm_handler_write(&session->stm, key);

  if (state == DONE || state == ERROR) {
    selector_unregister_fd(key->s, key->fd);
  }
}

static void socks5_client_block(struct selector_key *key) {
  client_t *session = key->data;
  stm_handler_block(&session->stm, key);
}

static void socks5_client_close(struct selector_key *key) {
  client_t *session = key->data;

  if (session == NULL) {
    return;
  }

  stm_handler_close(&session->stm, key);

  if (key->fd == session->client_fd) {
    session->client_fd = -1;
  } else if (key->fd == session->origin_fd) {
    session->origin_fd = -1;
  }

  session_destroy(session);
}

const struct fd_handler *get_session_handler(void) { return &session_handlers; }

static unsigned on_request_bind(struct selector_key *key) {
  client_t *s = key->data;

  request_reply rep = {
      .version = SOCKS5_VERSION,
      .status = 0x00,
      .rsv = 0x00,
  };

  if (!get_bound_addr(s->origin_fd, &rep.bnd)) {
    return ERROR;
  }

  char *out;
  unsigned int len;

  if (-1 == request_marshall(&rep, &out)) {
    return ERROR;
  }
  // chequear si hay q hacer free
  // free(out);
  selector_set_interest_key(key, OP_WRITE);
  return COPY; // TODO: cual es el siguiente estado (no se si es COPY)??????
}

static int get_bound_addr(int fd, reply_addr_t *addr) {
  struct sockaddr_storage s;
  socklen_t len = sizeof(s);
  if (getsockname(fd, (struct sockaddr *)&s, &len) < 0) {
    return 0;
  }
  if (s.ss_family == AF_INET) {
    struct sockaddr_in *ip4 = &s;
    addr->atyp = ATYP_IPV4;
    memcpy(addr->addr, &ip4->sin_addr, 4);
    addr->addr_len = 4;
    addr->port = ntohs(ip4->sin_port);
  } else if (s.ss_family == AF_INET6) {
    struct sockaddr_in6 *ip6 = &s;
    addr->atyp = ATYP_IPV6;
    memcpy(addr->addr, &ip6->sin6_addr, 16);
    addr->addr_len = 16;
    addr->port = ntohs(ip6->sin6_port);
  } else {
    // Tipo de address no soportado
    return 0;
  }
  return 1;
}

int build_reply(const request_reply *r, uint8_t **out_buf, size_t *out_len) {
  size_t addr_len;
  switch (r->bnd.atyp) {
  case ATYP_IPV4:
    addr_len = 4;
    break;
  case ATYP_DOMAIN:
    addr_len = 1 + r->bnd.addr_len;
    break;
  case ATYP_IPV6:
    addr_len = 16;
    break;
  default:
    return 0;
  }

  size_t tot = 4 + addr_len + 2;
  uint8_t *buf = malloc(tot);
  if (!buf) {
    return 0;
  }

  size_t pos = 0;
  buf[pos++] = r->version;
  buf[pos++] = r->status;
  buf[pos++] = 0x00;
  buf[pos++] = r->bnd.atyp;

  switch (r->bnd.atyp) {
  case ATYP_IPV4:
    memcpy(buf + pos, r->bnd.addr, 4);
    pos += 4;
    break;
  case ATYP_DOMAIN:
    buf[pos++] = r->bnd.addr_len;
    memcpy(buf + pos, r->bnd.addr, r->bnd.addr_len);
    pos += r->bnd.addr_len;
    break;
  case ATYP_IPV6:
    memcpy(buf + pos, r->bnd.addr, 16);
    pos += 16;
    break;
  }

  {
    uint16_t port = htons(r->bnd.port);
    memcpy(buf + pos, &port, 2);
  }
  *out_buf = buf;
  *out_len = tot;
  return 1;
}
