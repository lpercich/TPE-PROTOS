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

static unsigned on_hello_read(struct selector_key *key);
static unsigned on_hello_write(struct selector_key *key);
static unsigned on_auth_read(struct selector_key *key);
static unsigned on_auth_write(struct selector_key *key);

static const struct fd_handler session_handlers = {
    .handle_read = on_client_read,
    .handle_write = on_client_write,
    .handle_close = on_client_close,
};

static void session_destroy(client_t *session) {
  if (session != NULL) {
    if (session->client_fd >= 0) {
      close(session->client_fd);
    }
    free(session);
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

  // Inicializamos los buffers apuntando a los arrays internos
  buffer_init(&session->read_buffer, BUFFER_SIZE, session->read_memory);
  buffer_init(&session->write_buffer, BUFFER_SIZE, session->write_memory);

  socks5_init(session);

  hello_parser_init(&session->hello_parser);
  session->hello_parser.data = session;
  // inicializar los otros parsers

  return session;
}

// Handler de LECTURA: El cliente nos mandó datos.
static void on_client_read(struct selector_key *key) {
  client_t *session = key->data;

  unsigned state = stm_handler_read(&session->stm, key);

  if (state == ERROR || state == DONE) {
    selector_unregister_fd(key->s,
                           key->fd); // Cerrar si fallo o termino -> no deberia
                                     // ser unregister? Si, tenias razon
  }

  /* size_t wbytes;

  // 1. Me guarda en el puntero el lugar donde puedo escribir
  uint8_t *write_ptr = buffer_write_ptr(&session->read_buffer, &wbytes);

  // 2. Intentamos leer del socket (No bloqueante porque lo llama selector
  _select() en el main) ssize_t n = recv(key->fd, write_ptr, wbytes, 0);

  if (n <= 0) {
      // Si n=0 (cierre) o n<0 (error), cerramos la sesión.
      // Al desregistrar, el selector llamará automáticamente a on_client_close.
      selector_unregister_fd(key->s, key->fd);
      return; */
  /*  }

   // 3. Confirmamos que leímos 'n' bytes (valida que se haya leido
   correctamente) buffer_write_adv(&session->read_buffer, n);

   // --- LÓGICA DE ECO ---
   // Copiamos todo lo que entró en 'input_buffer' hacia 'output_buffer'
   while (buffer_can_read(&session->read_buffer)) {
       // Cuánto hay para leer del input?
       size_t rbytes;
       uint8_t *read_ptr = buffer_read_ptr(&session->read_buffer, &rbytes);

       // Cuánto espacio hay en el output?
       size_t available_space;
       uint8_t *out_ptr = buffer_write_ptr(&session->write_buffer,
   &available_space);

       // Copiamos el mínimo entre lo que tengo y lo que entra
       size_t copy_size = (rbytes < available_space) ? rbytes : available_space;
       memcpy(out_ptr, read_ptr, copy_size);

       buffer_read_adv(&session->read_buffer, copy_size);
       buffer_write_adv(&session->write_buffer, copy_size);
   }

   // 4. Como ahora tenemos datos para enviar, nos interesa el evento WRITE
   selector_set_interest(key->s, key->fd, OP_WRITE); */
}

// Handler de ESCRITURA: El socket está listo para enviar datos.
static void on_client_write(struct selector_key *key) {
  client_t *session = key->data;
  unsigned state = stm_handler_write(&session->stm, key);

  if (state == ERROR || state == DONE) {
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

// Handler de CIERRE: El socket se cerró.
static void on_client_close(struct selector_key *key) {
  client_t *session = key->data;
  printf("Cerrando conexión en fd %d\n", key->fd);
  session_destroy(session);
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

// AGREGO FUNCIONES PARA IR VIENDO ACCIONES CON STM

// CHEQUEAR EN TODAS las funcs SOCKS: deberia actualizar el estado con el ret de
// la funcion se stm???? lectura para socks5
static void socks5_client_read(struct selector_key *key) {
  client_t *session = key->data;
  stm_handler_read(&session->stm, key);
}

// escritura para socks
static void socks5_client_write(struct selector_key *key) {
  client_t *session = key->data;
  stm_handler_write(&session->stm, key);
}

static void socks5_client_block(struct selector_key *key) {
  client_t *session = key->data;
  stm_handler_block(&session->stm, key);
}

static void socks5_client_close(struct selector_key *key) {
  client_t *session = key->data;
  stm_handler_close(&session->stm, key);
}