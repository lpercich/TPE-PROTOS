#ifndef HELLO_H
#define HELLO_H

#include "buffer.h"
#include <stdbool.h>
#include <stdint.h>

#define SOCKS_HELLO_NOAUTHENTICATION_REQUIRED 0x00
#define SOCKS_HELLO_USERPASS_AUTH 0x02
#define SOCKS_HELLO_NO_ACCEPTABLE_METHODS 0xFF
#define SOCKS_VERSION 0x05

enum hello_state {
  HELLO_INITIAL,
  HELLO_READ_NMETHODS,
  HELLO_READ_METHODS,
  HELLO_DONE,
  HELLO_ERROR_STATE
};

struct hello_parser {
  void *data;
  void (*on_authentication_method)(struct hello_parser *p, uint8_t method);
  int state;
  uint8_t remaining;
  bool supports_no_auth;  
  bool supports_userpass; 
};

void hello_parser_init(struct hello_parser *p);
enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *errored);
bool hello_is_done(const enum hello_state st, bool *errored);
int hello_reply(buffer *b, const uint8_t method);

#endif
