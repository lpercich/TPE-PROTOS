#ifndef MNG_AUTH_H
#define MNG_AUTH_H
#define MAX_LENGTH 256
#include <stdint.h>
#include <stdbool.h>
#include "lib/buffer.h"


typedef enum {
    AUTH_CMD_START,
    AUTH_CMD_READING,
    AUTH_CMD_DONE,
    AUTH_CMD_ERROR
} mng_auth_state;

typedef struct{
    mng_auth_state state;
    char raw[MAX_LENGTH];  // lo que viene después de AUTH
    char buffer[MAX_LENGTH]; 
    int raw_len;
    int pos;
} mng_auth_parser;

typedef struct {
    char username[MAX_LENGTH];
    char password[MAX_LENGTH];
} auth_credentials;

mng_auth_state mng_auth_consume(buffer *b, mng_auth_parser *p, bool *errored);

#endif