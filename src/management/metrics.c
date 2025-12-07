#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>

static uint64_t historic_connections;
static uint64_t current_connections;
static uint64_t transferred_bytes;

void init_metrics() {
  historic_connections = 0;
  current_connections = 0;
  transferred_bytes = 0;
}

uint64_t get_historic_connections() { return historic_connections; }

uint64_t get_current_connections() { return current_connections; }

uint64_t get_transferred_bytes() { return transferred_bytes; }

void start_connection() {
  // agrgar máximo de conexiones ~ conexiones concurrentes ?
  historic_connections++;
  current_connections++;
}

void end_connection() { current_connections--; }

void transfer_bytes(uint64_t bytes) { transferred_bytes += bytes; }

uint8_t *write_metrics(void) {
  uint8_t *out = malloc(BUFSIZ);
  if (!out)
    return NULL;

  uint64_t total = get_historic_connections();
  uint64_t current = get_current_connections();
  uint64_t bytes = get_transferred_bytes();

  snprintf((char *)out, BUFSIZ,
           "+OK metrics\r\n"
           "total conections: %llu\r\n"
           "current conections: %llu\r\n"
           "total transfered bytes: %llu\r\n",
           (unsigned long long)total, (unsigned long long)current,
           (unsigned long long)bytes);

  return out;
}