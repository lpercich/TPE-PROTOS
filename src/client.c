#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h> // Necesario para select
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 4096

// Función para manejar el modo interactivo (tipo shell)
void interactive_mode(int sock) {
  fd_set readfds;
  char buf[BUF_SIZE];
  int max_fd = sock > STDIN_FILENO ? sock : STDIN_FILENO;

  printf("--- Interactive session initiated ---\n");
  printf("Available commands: \n\t METRICS: Print server metrics \n\t ADD_USER "
         "<username>:<password>: Add a new user  \n\t DEL_USER <username>: "
         "Delete a user \n\t LIST_USERS: List all users\n\t SHOW_LOGS: Show "
         "server logs\n\t SET_BUFFER <size>: Set buffer size\n\t QUIT: Exit "
         "the session\n\n");
  printf("-----------------------------------------------------------------\n");

  while (1) {
    // Limpiamos y configuramos los sets de descriptores
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds); // Escuchar teclado (fd 0)
    FD_SET(sock, &readfds);         // Escuchar servidor

    // Esperar actividad en alguno de los dos
    if (select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) {
      perror("select");
      break;
    }

    // 1. Si el SERVIDOR mandó datos (Respuesta)
    if (FD_ISSET(sock, &readfds)) {
      int n = recv(sock, buf, BUF_SIZE - 1, 0);
      if (n <= 0) {
        printf("\nServer closed the connection.\n");
        break;
      }
      buf[n] = 0;
      printf("%s", buf);
    }

    // 2. Si el USUARIO escribió algo (Comando)
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
      if (fgets(buf, BUF_SIZE, stdin) == NULL) {
        break; // EOF (Ctrl+D)
      }
      send(sock, buf, strlen(buf), 0);

      // Si el usuario escribió QUIT, podemos cortar localmente o esperar que el
      // server cierre
      if (strncasecmp(buf, "QUIT", 4) == 0) {
        break;
      }
    }
  }
}

int main(int argc, char *argv[]) {
  // Uso modificado: El comando final es opcional
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <ip> <port> <user>:<pass> [command...]\n",
            argv[0]);
    fprintf(stderr, "Interactive mode: ./client 127.0.0.1 8080 admin:1234\n");
    fprintf(stderr,
            "One-Shot mode:    ./client 127.0.0.1 8080 admin:1234 METRICS\n");
    return 1;
  }

  const char *ip = argv[1];
  int port = atoi(argv[2]);
  char *creds = argv[3]; // formato user:pass

  // 1. Conectar
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
    fprintf(stderr, "Invalid IP address\n");
    return 1;
  }

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect");
    return 1;
  }

  // 2. Autenticación Automática
  char auth_buf[1024];
  snprintf(auth_buf, sizeof(auth_buf), "AUTH %s\n", creds);
  send(sock, auth_buf, strlen(auth_buf), 0);

  // Leer respuesta de Auth
  char buf[BUF_SIZE];
  int n = recv(sock, buf, BUF_SIZE - 1, 0);
  if (n > 0) {
    buf[n] = 0;
    // Chequeo simple si la auth fue exitosa
    if (strstr(buf, "+OK") == NULL) {
      printf("Error Auth: %s", buf);
      close(sock);
      return 1;
    }
    // Si es interactivo mostramos que se logueó, sino silencio
    if (argc == 4)
      printf("Server: %s", buf);
  } else {
    perror("Error receiving auth response");
    close(sock);
    return 1;
  }

  // 3. Decidir Modo: ¿Hay argumentos extra?
  if (argc > 4) {
    // --- MODO ONE-SHOT ---
    char cmd[1024] = {0};
    for (int i = 4; i < argc; i++) {
      strcat(cmd, argv[i]);
      if (i < argc - 1)
        strcat(cmd, " ");
    }
    char final_cmd[1024];
    snprintf(final_cmd, sizeof(final_cmd), "%s\n", cmd);
    send(sock, final_cmd, strlen(final_cmd), 0);

    // Leer respuesta hasta que cierre o termine
    while ((n = recv(sock, buf, BUF_SIZE - 1, 0)) > 0) {
      buf[n] = 0;
      printf("%s", buf);
      // Si el buffer parece terminar el comando, cortamos para no quedarnos
      // colgados si el server no cierra la conexión. Pero lo ideal es usar el
      // modo interactivo.
      break;
    }
  } else {
    // --- MODO INTERACTIVO ---
    interactive_mode(sock);
  }

  close(sock);
  return 0;
}