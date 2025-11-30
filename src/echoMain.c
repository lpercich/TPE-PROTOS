#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include "lib/selector.h"

#include "server.h" 
#include "args.h"

static bool terminate = false;

// Handler para bajar el servidor con CTRL+C
static void sig_handler(const int signal) {
    printf("Señal %d recibida, terminando servidor...\n", signal);
    terminate = true;
}

// Crea y configura un socket pasivo TCP utilizando getaddrinfo. Soporta IPv4 e IPv6.
static int create_tcp_server_socket(const char *addr, const char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    // Permite IPv4 o IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE;    // Para usar en bind()

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

        // 1. Configurar SO_REUSEADDR (esto es para que el socket pueda ser reutilizado rápidamente, sino te quedas esperando a que lo liberen)
        int opt = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            perror("setsockopt(SO_REUSEADDR)");
            close(sfd);
            continue;
        }

        // 2. Si es IPv6, intentamos habilitar Dual Stack (para aceptar v4 también si es ::)
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
        fprintf(stderr, "No se pudo conectar a ninguna dirección\n");
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);

    if (listen(sfd, 20) < 0) { // CAMBIAR EL MAGIC VALUE (20), posiblemente por SOMAXCONN
        perror("listen");
        close(sfd);
        return -1;
    }

    return sfd;
}

int main(const int argc, char **argv) {
    // 1. Parsear argumentos (para obtener el puerto)
    struct socks5args args;
    parse_args(argc, argv, &args);

    // Convertir puerto a string para getaddrinfo
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", args.socks_port);

    // 2. Crear el socket del servidor usando create_tcp_server_socket
    int server_socket = create_tcp_server_socket(args.socks_addr, port_str);
    if (server_socket < 0) {
        fprintf(stderr, "Fallo iniciando servidor en %s:%s\n", args.socks_addr, port_str);
        return 1;
    }

    // 3. Configurar Socket Pasivo como NO BLOQUEANTE
    if (selector_fd_set_nio(server_socket) == -1) {
        perror("Fallo configurando server socket como no-bloqueante");
        close(server_socket);
        return 1;
    }

    // 4. Inicializar Selector. Como es pasivo no necesita write y close
    const struct fd_handler selector_handler = {
        .handle_read = echo_service_accept, 
        .handle_write = NULL,
        .handle_close = NULL,
    };

    struct selector_init conf = {
        .signal = SIGALRM, 
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 }
    };

    if (selector_init(&conf) != 0) {
        fprintf(stderr, "Fallo inicializando librería selector\n");
        close(server_socket);
        return 1;
    }

    fd_selector selector = selector_new(1024);
    if (selector == NULL) {
        fprintf(stderr, "Fallo creando instancia de selector\n");
        selector_close();
        close(server_socket);
        return 1;
    }

    selector_status ss = selector_register(selector, server_socket, &selector_handler, OP_READ, NULL);
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "Fallo registrando servidor: %s\n", selector_error(ss));
        selector_destroy(selector);
        selector_close();
        close(server_socket);
        return 1;
    }

    // 5. Loop principal
    //Configuro señales para poder terminar el programa con Ctrl+C
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    printf("Echo Server escuchando en %s:%s...\n", args.socks_addr, port_str);

    while (!terminate) {
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            fprintf(stderr, "Error en selector_select: %s\n", selector_error(ss));
            break;
        }
    }
    //Cierra los sockets
    if (selector != NULL) selector_destroy(selector);
    selector_close();
    close(server_socket);
    return 0;
}