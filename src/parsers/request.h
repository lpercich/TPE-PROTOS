#ifndef REQUEST_H
#define REQUEST_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

enum request_state {
    REQUEST_INITIAL,
    REQUEST_DONE,
    REQUEST_ERROR_STATE
};

struct request_parser {
    // TODO: Define fields
    int dummy;
};

void request_parser_init(struct request_parser *p);
enum request_state request_consume(buffer *b, struct request_parser *p, bool *errored);
bool request_is_done(const enum request_state st, bool *errored);
int request_marshall(buffer *b, const uint8_t status);

#endif
