#include <string.h>
#include "auth.h"

void auth_parser_init(struct auth_parser *p) {
    p->state = AUTH_VERSION_STATE;
    p->remaining = 0;
    p->pointer = 0;
    
    //Aseguro que los strings esten vacios
    memset(p->creds->username, 0, sizeof(p->creds->username));
    memset(p->creds->password, 0, sizeof(p->creds->password));
}

enum auth_state auth_consume(buffer *b, struct auth_parser *p, bool *errored) {
    enum auth_state st = p->state;
    
    while(buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);

        switch(st) {
            case AUTH_VERSION_STATE:
                if (c == 0x01) {
                    st = AUTH_ULEN_STATE;
                } else {
                    if (errored) *errored = true;
                    return AUTH_ERROR_STATE;
                }
                break;

            case AUTH_ULEN_STATE:
                p->remaining = c; //Guardo la longitud del string del username
                p->pointer = 0;
                if(p->remaining == 0) {
                    if (errored) *errored = true;
                    return AUTH_ERROR_STATE;
                }
                st = AUTH_USERNAME_STATE;
                break;

            case AUTH_USERNAME_STATE:
                p->creds->username[p->pointer++] = c;
                p->remaining--;
                if (p->remaining == 0) {
                    st = AUTH_PLEN_STATE;
                }
                break;

            case AUTH_PLEN_STATE:
                p->remaining = c; // Longitud del password
                p->pointer = 0;
                if (p->remaining == 0) {
                    // Password vacío es válido a veces, pero pasamos a DONE
                    st = AUTH_DONE_STATE; 
                } else {
                    st = AUTH_PASSWORD_STATE;
                }
                break;

            case AUTH_PASSWORD_STATE:
                p->creds->password[p->pointer++] = c;
                p->remaining--;
                if (p->remaining == 0) {
                    st = AUTH_DONE_STATE;
                }
                break;

            case AUTH_DONE_STATE:
            case AUTH_ERROR_STATE:
                // No consumimos más
                return st;
        }
    }
    p->state = st;
    return st;
}
                
bool auth_is_done(const enum auth_state st, bool *errored) {
    if (st == AUTH_ERROR_STATE && errored) *errored = true;
    return st == AUTH_DONE_STATE;
}

int auth_marshall(buffer *b, const uint8_t status) {
    if (buffer_can_write(b)) {
        size_t n;
        uint8_t *buf = buffer_write_ptr(b, &n);
        if (n < 2) return -1;

        buf[0] = 0x01;   // Versión Auth
        buf[1] = status; // 0x00 Success, 0x01 Failure
        buffer_write_adv(b, 2);
        return 2;
    }
    return -1;
}