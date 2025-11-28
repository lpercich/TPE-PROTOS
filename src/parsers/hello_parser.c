#include "hello.h"

void hello_parser_init(struct hello_parser *p) {
    (void)p;
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored) {
    (void)b;
    (void)p;
    if (errored) *errored = false;
    return HELLO_DONE;
}

bool hello_is_done(const enum hello_state st, bool *errored) {
    (void)errored;
    return st == HELLO_DONE;
}

int hello_marshall(buffer *b, const uint8_t method) {
    (void)b;
    (void)method;
    return 0;
}
