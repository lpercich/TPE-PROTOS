#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LOGS 50
#define LOG_ENTRY_SIZE 256

static char access_log[MAX_LOGS][LOG_ENTRY_SIZE];
static int log_head = 0;
static int log_count = 0;

void log_access(const char *user, const char *src_addr, const char *dst_addr,
                const char *status) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char time_str[64];

  strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", t);

  // Formato: [TIMESTAMP] user=USERNAME src=IP:PORT dst=ADDR:PORT status=STATUS
  char entry[LOG_ENTRY_SIZE];
  snprintf(entry, sizeof(entry), "[%s] user=%s src=%s dst=%s status=%s\n",
           time_str, user ? user : "unknown", src_addr ? src_addr : "unknown",
           dst_addr ? dst_addr : "unknown", status ? status : "unknown");

  fputs(entry, stdout);

  strncpy(access_log[log_head], entry, LOG_ENTRY_SIZE - 1);
  access_log[log_head][LOG_ENTRY_SIZE - 1] = '\0';

  log_head = (log_head + 1) % MAX_LOGS;
  if (log_count < MAX_LOGS) {
    log_count++;
  }
}

char *read_access_logs(void) {
  size_t total_size = log_count * LOG_ENTRY_SIZE + 1;
  char *buffer = malloc(total_size);
  if (!buffer)
    return NULL;

  buffer[0] = '\0';
  int start = (log_count < MAX_LOGS) ? 0 : log_head;

  for (int i = 0; i < log_count; i++) {
    int idx = (start + i) % MAX_LOGS;
    strncat(buffer, access_log[idx], total_size - strlen(buffer) - 1);
  }

  return buffer;
}
