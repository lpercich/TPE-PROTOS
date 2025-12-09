#ifndef METRICS_H
#define METRICS_H
#include <stdint.h>

typedef enum {
  AUTH,
  METRICS,
  ADD_USER,
  DEL_USER,
  LIST_USERS,
  SHOW_LOGS,
  SET_BUFFER,
  QUIT,
  UNKNOWN,
} mng_cmd;

uint8_t *write_metrics(void);
void init_metrics();
uint64_t get_historic_connections();
uint64_t get_current_connections();
uint64_t get_transferred_bytes();
void start_connection();
void end_connection();
void transfer_bytes(uint64_t bytes);

#endif