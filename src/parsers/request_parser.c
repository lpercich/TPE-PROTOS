#include "request.h"
#include <string.h>
#include <arpa/inet.h>


void request_parser_init(request_parser *parser) {
    memset(parser, 0, sizeof(*parser));
    parser->ver = 0;
    parser->cmd = 0;
    parser->atyp = 0;
    parser->addr_len = 0;
    parser->pos = 0;
    parser->port = 0;
}

//chequear esta funcion
request_state request_consume(buffer *buffer, request_parser *p, bool *errored) {
    if (errored) *errored = false;

    size_t n;
    uint8_t *ptr;

    while (1) {
        ptr = buffer_read_ptr(buffer, &n);
        if (n == 0)
            return REQUEST_INITIAL;

        uint8_t c = *ptr;

        //version
        if (p->pos == 0) {
            p->ver = c;
            if (p->ver != SOCKS5_VERSION) {
                if (errored) *errored = true;
                return REQUEST_ERROR_STATE;
            }
            p->pos++;

        //command
        } else if (p->pos == 1) {
            p->cmd = c;
            p->pos++;

        //rsv (0)
        } else if (p->pos == 2) {
            if (c != 0x00) {
                if (errored) *errored = true;
                return REQUEST_ERROR_STATE;
            }
            p->pos++;

        //atyp
        } else if (p->pos == 3) {
            p->atyp = (address_type)c;

            if (p->atyp != ATYP_IPV4 &&
                p->atyp != ATYP_DOMAIN &&
                p->atyp != ATYP_IPV6) {
                if (errored) *errored = true;
                return REQUEST_ERROR_STATE;
            }
            p->pos++;

        // a partir de acá depende del ATYP
        } else {

            if (p->atyp == ATYP_IPV4) {

                if (p->pos >= 4 && p->pos < 8) {             // 4 bytes dirección
                    p->addr[p->pos - 4] = c;
                    p->pos++;

                } else if (p->pos == 8) {                    // primer byte del puerto
                    p->port = (c << 8);
                    p->pos++;

                } else if (p->pos == 9) {                    // segundo byte del puerto
                    p->port |= c;
                    buffer_read_adv(buffer, 1);
                    return REQUEST_DONE;
                }

            } else if (p->atyp == ATYP_DOMAIN) {

                 if (p->pos == 4) {
                    p->addr_len = c;
                    if (p->addr_len == 0 || p->addr_len > 255) {
                        if (errored) *errored = true;
                        return REQUEST_ERROR_STATE;
                        }
                    p->pos++;
                } else if (p->pos >= 5 && p->pos < 5 + p->addr_len) {  
                    p->addr[p->pos - 5] = c;                 // nombre del dominio
                    p->pos++;

                } else if (p->pos == 5 + p->addr_len) {      // primer byte del puerto
                    p->port = (c << 8);
                    p->pos++;

                } else if (p->pos == 6 + p->addr_len) {      // segundo byte 
                    p->port |= c;
                    buffer_read_adv(buffer, 1);
                    return REQUEST_DONE;
                }

            } else if (p->atyp == ATYP_IPV6) {

                if (p->pos >= 4 && p->pos < 20) {            // 16 bytes IPv6
                    p->addr[p->pos - 4] = c;
                    p->pos++;

                } else if (p->pos == 20) {                   // puerto byte 1
                    p->port = (c << 8);
                    p->pos++;

                } else if (p->pos == 21) {                   // puerto byte 2 
                    p->port |= c;
                    buffer_read_adv(buffer, 1);
                    return REQUEST_DONE;
                }
            }
        }

        // avanzamos un byte del buffer
        buffer_read_adv(buffer, 1);
    }

    return REQUEST_INITIAL;
}

bool request_is_done(const request_state state, bool *errored) {
    if (errored && *errored) return true;
    return state == REQUEST_DONE;
}

int request_marshall(buffer *buffer, request_reply *reply) {
    size_t space;
    uint8_t *out = buffer_write_ptr(buffer, &space);

    // El tamaño mínimo de reply son 10 bytes (IPv4)
    size_t addr_bytes;

    switch (reply->bnd.atyp) {
        case ATYP_IPV4:
            addr_bytes = 4;
            break;

        case ATYP_DOMAIN:
            addr_bytes = 1 + reply->bnd.addr_len;   // length + bytes
            break;

        case ATYP_IPV6:
            addr_bytes = 16;
            break;

        default:
            return -1;  
    }

    const size_t needed = 4 + addr_bytes + 2 ; //4: header fijo, 2: puerto

    if (space < needed) {
        return -1;   
    }

    // Construimos la reply
    // Header fijo
    out[0] = reply->version;
    out[1] = reply->status;
    out[2] = 0x00;               // RSV siempre 0x00
    out[3] = reply->bnd.atyp;

    size_t cursor = 4;

    // Dirección según ATYP
    if (reply->bnd.atyp == ATYP_IPV4) {
        memcpy(out + cursor, reply->bnd.addr, 4);
        cursor += 4;

    } else if (reply->bnd.atyp == ATYP_DOMAIN) {
        out[cursor++] = reply->bnd.addr_len;
        memcpy(out + cursor, reply->bnd.addr, reply->bnd.addr_len);
        cursor += reply->bnd.addr_len;

    } else {  // IPv6
        memcpy(out + cursor, reply->bnd.addr, 16);
        cursor += 16;
    }

    // Puerto en network order
    uint16_t p = htons(reply->bnd.port); //host to network
    memcpy(out + cursor, &p, 2);
    cursor += 2;

    // Confirmamos en el buffer que escribimos cursor bytes
    buffer_write_adv(buffer, cursor);

    return 0;
}

