#include "lib/selector.h"
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "args.h"
#include "management/mng_prot.h"
#include "server.h"

static bool terminate = false;

// Handler para bajar el servidor con CTRL+C
static void sig_handler(const int signal) {
  printf("Signal %d received, shutting down server...\n", signal);
  terminate = true;
}

// Crea y configura un socket pasivo TCP utilizando getaddrinfo. Soporta IPv4 e
// IPv6.
static int create_tcp_server_socket(const char *addr, const char *port) {
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sfd = -1;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;     // Permite IPv4 o IPv6
  hints.ai_socktype = SOCK_STREAM; // TCP
  hints.ai_flags = AI_PASSIVE;     // Para usar en bind()

  int s = getaddrinfo(addr, port, &hints, &result);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return -1;
  }

  // Iterar sobre las direcciones encontradas hasta lograr bind
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1)
      continue;

    // 1. Configurar SO_REUSEADDR (esto es para que el socket pueda ser
    // reutilizado rápidamente, sino te quedas esperando a que lo liberen)
    int opt = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
      perror("setsockopt(SO_REUSEADDR)");
      close(sfd);
      continue;
    }

    // 2. Si es IPv6, intentamos habilitar Dual Stack (para aceptar v4 también
    // si es ::)
    if (rp->ai_family == AF_INET6) {
      int no = 0;
      // Ignoramos error si falla, no es crítico para que levante
      setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
    }

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break; // Éxito

    close(sfd); // Fallo bind, cerramos e intentamos siguiente
  }

  if (rp == NULL) {
    fprintf(stderr, "Could not connect to any address\n");
    freeaddrinfo(result);
    return -1;
  }

  freeaddrinfo(result);

  if (listen(sfd, 20) <
      0) { // CAMBIAR EL MAGIC VALUE (20), posiblemente por SOMAXCONN
    perror("listen");
    close(sfd);
    return -1;
  }

  if (selector_fd_set_nio(sfd) == -1) {
    perror("selector_fd_set_nio");
    close(sfd);
    return -1;
  }

  return sfd;
}

#include "management/mng_users.h"

int main(const int argc, char **argv) {
  // 1. Parsear argumentos (para obtener el puerto)
  struct socks5args args;
  parse_args(argc, argv, &args);

  // Inicializar usuarios de gestión
  init_users();

  setbuf(stdout, NULL);

  // Convertir puerto a string para getaddrinfo
  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%d", args.socks_port);

  // 2. Crear el socket del servidor usando create_tcp_server_socket
  int server_socket = create_tcp_server_socket(args.socks_addr, port_str);
  if (server_socket < 0) {
    fprintf(stderr, "Failed to start server on %s:%s\n", args.socks_addr,
            port_str);
    return 1;
  }

  // 3. Configurar Socket Pasivo como NO BLOQUEANTE
  if (selector_fd_set_nio(server_socket) == -1) {
    perror("Failed to set server socket as non-blocking\n");
    close(server_socket);
    return 1;
  }

  // 4. Inicializar Selector. Como es pasivo no necesita write y close
  // SELECTOR PARA ACEPTAR CONEXIONES
  const struct fd_handler selector_handler = {
      .handle_read = echo_service_accept,
      .handle_write = NULL,
      .handle_close = NULL,
  };

  struct selector_init conf = {.signal = SIGALRM,
                               .select_timeout = {.tv_sec = 10, .tv_nsec = 0}};

  if (selector_init(&conf) != 0) {
    fprintf(stderr, "Failed to initialize selector library\n");
    close(server_socket);
    return 1;
  }

  fd_selector selector = selector_new(1024);
  if (selector == NULL) {
    fprintf(stderr, "Failed to create selector instance\n");
    selector_close();
    close(server_socket);
    return 1;
  }

  // Pasamos &args como data para que el handler pueda acceder a los usuarios
  // configurados
  selector_status ss = selector_register(selector, server_socket,
                                         &selector_handler, OP_READ, &args);
  if (ss != SELECTOR_SUCCESS) {
    fprintf(stderr, "Failed to register server: %s\n", selector_error(ss));
    selector_destroy(selector);
    selector_close();
    close(server_socket);
    return 1;
  }

  // 4b. Inicializar Servidor de Gestión (MNG)
  char mng_port_str[8];
  snprintf(mng_port_str, sizeof(mng_port_str), "%d", args.mng_port);

  int mng_socket = create_tcp_server_socket(args.mng_addr, mng_port_str);
  if (mng_socket < 0) {
    fprintf(stderr, "Failed to start management server on %s:%s\n",
            args.mng_addr, mng_port_str);
    // No es fatal, podemos seguir sin gestión o abortar. La consigna implica
    // que es parte del sistema. Abortamos para ser seguros.
    selector_destroy(selector);
    selector_close();
    close(server_socket);
    return 1;
  }

  if (selector_fd_set_nio(mng_socket) == -1) {
    perror("Failed to configure mng socket as non-blocking");
    close(mng_socket);
    selector_destroy(selector);
    selector_close();
    close(server_socket);
    return 1;
  }

  const struct fd_handler mng_handler = {
      .handle_read = mng_passive_accept,
      .handle_write = NULL,
      .handle_close = NULL,
  };

  ss = selector_register(selector, mng_socket, &mng_handler, OP_READ, &args);
  if (ss != SELECTOR_SUCCESS) {
    fprintf(stderr, "Failed to register management server: %s\n",
            selector_error(ss));
    close(mng_socket);
    selector_destroy(selector);
    selector_close();
    close(server_socket);
    return 1;
  }

  // 5. Loop principal
  // Configuro señales para poder terminar el programa con Ctrl+C
  signal(SIGTERM, sig_handler);
  signal(SIGINT, sig_handler);

  printf("SOCKS5 Server listening on %s:%s...\n", args.socks_addr, port_str);

  while (!terminate) {
    ss = selector_select(selector);
    if (ss != SELECTOR_SUCCESS) {
      fprintf(stderr, "Error in selector_select: %s\n", selector_error(ss));
      break;
    }
  }
  // Cierra los sockets
  if (selector != NULL)
    selector_destroy(selector);
  selector_close();
  close(server_socket);
  return 0;
}