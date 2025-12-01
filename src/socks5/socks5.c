#include <socks5.h>
#include <hello.h>

static const struct state_definition socks5_states[] = {
    [HELLO_READ]{
        .state = HELLO_READ,
        .on_arrival = hello_parser_init, 
        .on_read  =  hello_consume,
    },
    [HELLO_WRITE]{
        .state = HELLO_WRITE,
        .on_write = hello_reply,
    },
};


