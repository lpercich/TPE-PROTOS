#include "mng_auth.h"
#include "mng_prot.h"
#include <string.h>

mng_auth_state mng_auth_consume(buffer *b, mng_auth_parser *p, bool *errored) {
    mng_auth_state st = p->state;

    while(buffer_can_read(b)) {
        uint8_t c = buffer_read(b);

        switch(st) {

        case AUTH_CMD_START:
            p->pos = 0;
            if (c == '\r' || c == '\n') {
                break;
            }
            st = AUTH_CMD_READING;

        case AUTH_CMD_READING:
            if (c == '\r') {
                break;
            }
            if (c == '\n') {
                // comando completo
                p->buffer[p->pos] = '\0';
                return AUTH_CMD_DONE;
            }

            if (p->pos >= sizeof(p->buffer)-1) {
                if (errored) *errored = true;
                return AUTH_CMD_ERROR;
            }

            p->buffer[p->pos++] = c;
            break;

        case AUTH_CMD_DONE:
        case AUTH_CMD_ERROR:
            return st;
        }
    }

    p->state = st;
    return st;
}

