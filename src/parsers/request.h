#ifndef REQUEST_H
#define REQUEST_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#define SOCKS5_VERSION 0x05

typedef enum{
    REQUEST_INITIAL,
    REQUEST_DONE,
    REQUEST_ERROR_STATE
}request_state;

typedef enum{
    ATYP_IPV4   = 0x01,
    ATYP_DOMAIN = 0x03,
    ATYP_IPV6   = 0x04
}address_type;

typedef struct {
    uint8_t ver; //version
    uint8_t cmd; //esto tmb podria sdr un enum
    address_type atyp; 
    uint8_t addr[256];  //direccion destino
    uint16_t port;
    uint8_t pos;    //cuantos bytes del request fueron procesados    
    uint8_t addr_len; //longitud del dominio si atyp es domain  
    uint8_t state_end; // posición del último byte
} request_parser;

typedef struct {
    address_type atyp;       // IPv4 / domain / IPv6
    uint8_t addr[256];       // dirección 
    uint8_t addr_len;        // para domain
    uint16_t port;           // puerto origen para la reply
} reply_addr_t;

typedef struct {
    uint8_t version;         // siempre 0x05
    uint8_t status;          // REP
    reply_addr_t bnd;        // dirección reportada por el servidor (bnd.addr del RFC)
} request_reply;


void request_parser_init(request_parser *parser);
request_state request_consume(buffer *buffer, request_parser *parser, bool *errored);
bool request_is_done(const request_state state, bool *errored);
int request_marshall(buffer *buffer, request_reply *reply);

#endif
