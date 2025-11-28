#include "request.h"

void request_parser_init(struct request_parser *p) {
    (void)p;
}

enum request_state request_consume(buffer *b, struct request_parser *p, bool *errored) {
    (void)b;
    (void)p;
    if (errored) *errored = false;
    return REQUEST_DONE;
}

bool request_is_done(const enum request_state st, bool *errored) {
    (void)errored;
    return st == REQUEST_DONE;
}

int request_marshall(buffer *b, const uint8_t status) {
    (void)b;
    (void)status;
    return 0;
}
