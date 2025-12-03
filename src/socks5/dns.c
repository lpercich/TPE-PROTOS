#include <dns.h>

//CHEQUEAR!!!!!!
void * dns_resolve(void* s_key){
struct selector_key* key = (struct selector_key *) s_key;
client_t *s = key->data;
struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
        .ai_protocol = 0,
        .ai_canonname = NULL,
        .ai_addr = NULL,
        .ai_next = NULL,
    };

    char port[10];
    sprintf(port, "%d", s->request_parser.port);

    int error = getaddrinfo(s->request_parser.addr, port, &hints, &s->res_addr);
    if(error){
        s->res_addr=NULL; 
    } 
    s->current_res=s->res_addr;

    selector_notify_block(key->s, key->fd);

    free(s_key);

    return NULL;

}