#ifndef HELLO_H
#define HELLO_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define SOCKS_HELLO_NOAUTHENTICATION_REQUIRED 0x00
#define SOCKS_HELLO_NO_ACCEPTABLE_METHODS 0xFF

enum hello_state {
    HELLO_INITIAL,
    HELLO_DONE,
    HELLO_ERROR_STATE
};

struct hello_parser {
    void *data;
    void (*on_authentication_method)(struct hello_parser *p, uint8_t method);
};

void hello_parser_init(struct hello_parser *p);
enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored);
bool hello_is_done(const enum hello_state st, bool *errored);
int hello_marshall(buffer *b, const uint8_t method);

#endif
