#include <stdlib.h>
#include <stdio.h>
#include "hello.h"

void hello_parser_init(struct hello_parser *p) {
    p->state = 0;
    p->remaining = 0;
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored) {
    enum hello_state state = p->state;
    
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        
        switch(state) {
            case HELLO_INITIAL:
                if(c == 0x05) {
                    state = HELLO_READ_NMETHODS; //pasamos a leer NMETHODS
                } else {
                    if(errored) *errored = true;
                    return HELLO_ERROR_STATE;
                }
                break;
            case HELLO_READ_NMETHODS: //leyendo NMETHODS
                p->remaining = c;
                if(p->remaining > 0) {
                    state = HELLO_READ_METHODS; //pasamos a leer METHODS
                } else {
                    state = HELLO_DONE;
                }
                break;
            case HELLO_READ_METHODS: //leyendo METHODS
                //Por ahora solo consumimos los metodos
                if(p->on_authentication_method) {
                    p->on_authentication_method(p, c);
                }
                p->remaining--;
                if(p->remaining == 0) {
                    state = HELLO_DONE;
                }
                break;
            case HELLO_DONE:
            case HELLO_ERROR_STATE:
                //si terminamos no consumimos mas aunque haya bytes
                return state;
        }
    }
    p->state = state;
    return state;
}

bool hello_is_done(const enum hello_state state, bool *errored) {
    if(state == HELLO_ERROR_STATE && errored) *errored = true;
    return state == HELLO_DONE;
}

int hello_reply(buffer *b, const uint8_t method) {
    if(buffer_can_write(b)) {
        size_t n;
        uint8_t *buf = buffer_write_ptr(b, &n);
        if(n < 2) return -1;
        
        buf[0] = 0x05;
        buf[1] = method;
        buffer_write_adv(b, 2);
        return 2;
    }
    return -1;
}
