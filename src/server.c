#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "args.h"
#include "lib/buffer.h"
#include "lib/selector.h"
#include "parsers/auth.h"
#include "parsers/hello.h"
#include "server.h"
#include "socks5/socks5.h"
#include "stm.h"

static void on_client_read(struct selector_key *key);
static void on_client_write(struct selector_key *key);
static void on_client_close(struct selector_key *key);
static void on_client_block(struct selector_key *key);

static unsigned on_hello_read(struct selector_key *key);
static unsigned on_hello_write(struct selector_key *key);
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_auth_write(struct selector_key *key);

const struct fd_handler session_handlers = {
    .handle_read = on_client_read,
    .handle_write = on_client_write,
    .handle_close = on_client_close,
    .handle_block = on_client_block,
};

void session_destroy(client_t *session) {
  if (session != NULL) {
    session->references--;
    if (session->references == 0) {
      if (session->client_fd >= 0) {
        close(session->client_fd);
      }
      if (session->origin_fd >= 0) {
        close(session->origin_fd);
      }
      free(session);
    }
  }
}

// crea una nueva session
static client_t *session_new(int fd) {
  client_t *session = malloc(sizeof(client_t));
  if (session == NULL) {
    return NULL;
  }
  memset(session, 0, sizeof(client_t));

  session->client_fd = fd;
  session->origin_fd = -1;
  session->close_after_write = false;
  session->references = 1;

  // Inicializamos los buffers apuntando a los arrays internos
  buffer_init(&session->read_buffer, BUFFER_SIZE, session->read_memory);
  buffer_init(&session->write_buffer, BUFFER_SIZE, session->write_memory);

  socks5_init(session);

  hello_parser_init(&session->hello_parser);
  session->hello_parser.data = session;

  return session;
}

// Handler de LECTURA: El cliente nos mandó datos.
static void on_client_read(struct selector_key *key) {
  client_t *session = key->data;

  unsigned state = stm_handler_read(&session->stm, key);

  if (state == ERROR || state == DONE) {
    int other_fd = (key->fd == session->client_fd) ? session->origin_fd
                                                   : session->client_fd;
    selector_unregister_fd(key->s, key->fd);
    if (other_fd >= 0) {
      selector_unregister_fd(key->s, other_fd);
    }
  }
}

// Handler de ESCRITURA: El socket está listo para enviar datos.
static void on_client_write(struct selector_key *key) {
  client_t *session = key->data;
  unsigned state = stm_handler_write(&session->stm, key);

  if (state == ERROR || state == DONE) {
    int other_fd = (key->fd == session->client_fd) ? session->origin_fd
                                                   : session->client_fd;
    selector_unregister_fd(key->s, key->fd);
    if (other_fd >= 0) {
      selector_unregister_fd(key->s, other_fd);
    }
  }
}

// Handler de CIERRE: El socket se cerró.
static void on_client_close(struct selector_key *key) {
  client_t *session = key->data;
  printf("Cerrando conexión en fd %d\n", key->fd);
  session_destroy(session);
}

// Handler de BLOQUEO: Tarea bloqueante finalizó (ej: DNS)
static void on_client_block(struct selector_key *key) {
  client_t *session = key->data;
  unsigned state = stm_handler_block(&session->stm, key);

  if (state == ERROR || state == DONE) {
    int other_fd = (key->fd == session->client_fd) ? session->origin_fd
                                                   : session->client_fd;
    selector_unregister_fd(key->s, key->fd);
    if (other_fd >= 0) {
      selector_unregister_fd(key->s, other_fd);
    }
  }
}

// Handler PÚBLICO: Acepta nuevas conexiones SOCKS5.
void socksv5_passive_accept(struct selector_key *key) {
  struct socks5args *args =
      key->data; // Obtenemos la configuración del servidor
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  // 1. Aceptar conexión entrante
  int new_fd =
      accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
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
  selector_status ss = selector_register(key->s, new_fd, &session_handlers,
                                         OP_READ, new_session);

  if (ss != SELECTOR_SUCCESS) {
    fprintf(stderr, "Error registrando cliente en selector: %s\n",
            selector_error(ss));
    session_destroy(new_session); // Esto cierra el fd y libera memoria
    return;
  }

  printf("Nueva conexión aceptada en fd %d\n", new_fd);
}
