#ifndef MNG_H
#define MNG_H
#include "buffer.h"
#include "args.h"
#include "mng_auth.h"
#include "mng_users.h"
#include "metrics.h"
#include <stdint.h>
#include <stdlib.h>
#define BUFFER_SIZE 256
#define CMD_SIZE 16
#define ARG_SIZE 128

typedef enum {
    MNG_AUTH,
    MNG_AUTH_REPLY,
    MNG_CMD_READ,
    MNG_CMD_WRITE,
    MNG_DONE,
    MNG_ERROR,
} mng_state;



typedef struct {
    mng_cmd cmd;
    int fd;
    buffer read_buffer;
    buffer write_buffer;
    user_t users[MAX_USERS]; //esto esta como global ¿¿??
    int user_count; //idem users
    mng_auth_parser mng_auth_parser;
    char arg[ARG_SIZE];   // único argumento (user o user:pass)
    auth_credentials credentials; // aca guardamos user/pass recibidos
    bool auth_success;            // resultado de la validación de credenciales

}metrics_t;


#endif