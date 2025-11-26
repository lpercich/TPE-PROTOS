#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include "selector.h"
#include "buffer.h"
#include "netutils.h"
#include "parser.h"
#include "parser_utils.h"
#include "stm.h"





#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 30

int main(){
    int server_fd, new_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    fd_set read_fds;
    fd_set master_fds;
    int fdmax;

    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    //Aca no se si seria max clients
    if(listen(server_fd, MAX_CLIENTS) == -1) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    FD_ZERO(&master_fds);
    FD_ZERO(&read_fds);

    FD_SET(server_fd, &master_fds);
    fdmax = server_fd;

    printf("Server listening on port %d\n", PORT);

    while(1) {
        read_fds = master_fds;

        if(select(fdmax + 1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("Select failed");
            exit(EXIT_FAILURE);
        }

        for(int i = 0; i <= fdmax; i++) {
            if(FD_ISSET(i, &read_fds)) {

                if(i == server_fd) {
                    struct sockaddr_in client_addr;
                    socklen_t client_addr_len = sizeof(client_addr);
                    new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);

                    if(new_socket == -1) {
                        perror("Accept failed");
                    } else {
                        FD_SET(new_socket, &master_fds);
                        if(new_socket > fdmax) {
                            fdmax = new_socket;
                        }
                        char client_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                        printf("New connection from %s:%d on socket %d\n",client_ip, ntohs(client_addr.sin_port), new_socket);
                    }
                }
                else {
                    ssize_t nbytes;
                    if((nbytes = recv(i, buffer, sizeof(buffer) - 1, 0)) <= 0) {
                        if(nbytes == 0) {
                            printf("Socket %d disconnected\n", i);
                        } else {
                            perror("Recv failed");
                        }
                        close(i);
                        FD_CLR(i, &master_fds);
                    } else {
                        printf("Received data on socket %d: %.*s\n", i, (int)nbytes, buffer);
                        if(write(i, buffer, nbytes) < 0) {
                            perror("Write failed");
                        }

                    }
                }

            }
        }
    }


}