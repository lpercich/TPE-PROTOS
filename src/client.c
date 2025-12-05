#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 4096

int main(int argc, char *argv[]) {
  // Uso: ./client <ip> <port> <user>:<pass> <cmd>
  if (argc < 5) {
    fprintf(stderr, "Uso: %s <ip> <port> <user>:<pass> <comando...>\n",
            argv[0]);
    fprintf(stderr, "Ej: ./client 127.0.0.1 8080 admin:1234 METRICS\n");
    return 1;
  }

  const char *ip = argv[1];
  int port = atoi(argv[2]);
  char *creds = argv[3]; // formato user:pass

  // Concatenar el resto de argumentos para formar el comando (ej: "ADD_USER
  // pepe:123")
  char cmd[1024] = {0};
  for (int i = 4; i < argc; i++) {
    strcat(cmd, argv[i]);
    if (i < argc - 1)
      strcat(cmd, " ");
  }

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
    fprintf(stderr, "IP invalida\n");
    return 1;
  }

  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect");
    return 1;
  }

  // 2. Autenticar
  char auth_buf[1024];
  snprintf(auth_buf, sizeof(auth_buf), "AUTH %s\n", creds);
  send(sock, auth_buf, strlen(auth_buf), 0);

  // Leer respuesta de Auth
  char buf[BUF_SIZE];
  int n = recv(sock, buf, BUF_SIZE - 1, 0);
  if (n > 0) {
    buf[n] = 0;
    printf("Servidor: %s", buf);
    if (strstr(buf, "+OK") == NULL) { // Si no dice +OK, cortamos
      close(sock);
      return 1;
    }
  }

  // 3. Enviar Comando Real
  char final_cmd[1024];
  snprintf(final_cmd, sizeof(final_cmd), "%s\n", cmd);
  send(sock, final_cmd, strlen(final_cmd), 0);

  // 4. Imprimir Respuesta
  while ((n = recv(sock, buf, BUF_SIZE - 1, 0)) > 0) {
    buf[n] = 0;
    printf("%s", buf);
  }

  close(sock);
  return 0;
}
