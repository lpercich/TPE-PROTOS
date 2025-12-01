#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

//Estados internos del parser de autenticacion
enum auth_state {
    AUTH_VERSION_STATE,
    AUTH_ULEN_STATE,
    AUTH_USERNAME_STATE,
    AUTH_PLEN_STATE,
    AUTH_PASSWORD_STATE,
    AUTH_DONE_STATE,
    AUTH_ERROR_STATE
};

//Estructura que contiene las credenciales leidas
typedef struct {
    char username[256];
    char password[256];
} auth_credentials;

//Estructura del parser de autenticacion
struct auth_parser {
    enum auth_state state;
    uint8_t remaining;      //Para contar bytes de strings variables
    uint8_t pointer;        //Cursor para escribir en los arrays de chars
    auth_credentials *creds; //Puntero donde se guardan las credenciales
};

void auth_parser_init(struct auth_parser *p);
enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored);
bool auth_is_done(const enum auth_state st, bool *errored);
int auth_marshall(buffer *buffer, const uint8_t status);

#endif
