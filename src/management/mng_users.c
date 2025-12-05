#include "mng_users.h"
#include "../args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static user_t users[MAX_USERS];
static int user_count = 0;

bool init_users(void) {
  user_count = 0;
  const char *admin = getenv("ADMIN");
  char *username, *password;
  if (admin) {
    parse_user(admin, &username, &password);
    if (username && password) {
      add_user(username, password);
    }
  }

  return true;
}

void parse_user(const char *user, char **username, char **password) {
  if (user == NULL | username == NULL | password == NULL) {
    return;
  }
  char *separator = strchr(user, ':');
  if (separator == NULL) {
    *username = NULL;
    *password = NULL;
    return;
  }
  size_t user_length = separator - user;
  size_t password_length = strlen(separator + 1);
  *username = malloc(user_length + 1);
  *password = malloc(password_length + 1);

  if (*username == NULL || *password == NULL) {
    free(*username);
    free(*password);
    *username = NULL;
    *password = NULL;
    return;
  }
  memcpy(*username, user, user_length);
  (*username)[user_length] = '\0';

  memcpy(*password, separator + 1, password_length);
  (*password)[password_length] = '\0';
}

bool add_user(const char *username, const char *password) {
  if (!username || !password)
    return false;

  for (int i = 0; i < user_count; i++) {
    if (users[i].is_active && strcmp(users[i].username, username) == 0) {

      return false;
    }
  }

  for (int i = 0; i < user_count; i++) {
    if (!users[i].is_active) {
      users[i].username = strdup(username);
      users[i].password = strdup(password);
      users[i].is_active = true;
      return true;
    }
  }

  if (user_count >= MAX_USERS)
    return false;

  users[user_count].username = strdup(username);
  users[user_count].password = strdup(password);
  users[user_count].is_active = true;
  user_count++;
  return true;
}

bool del_user(char *username) {
  if (!username)
    return false;

  for (int i = 0; i < user_count; i++) {
    if (users[i].is_active && strcmp(users[i].username, username) == 0) {
      users[i].is_active = false;
      free(users[i].username);
      free(users[i].password);
      return true;
    }
  }

  return false;
}

char *list_users() {
  static char buf[4096];
  int pos = 0;
  buf[0] = '\0';

  for (int i = 0; i < user_count; i++) {
    if (users[i].is_active) {
      int written =
          snprintf(buf + pos, strlen(buf) - pos, "%s \n", users[i].username);
      if (written < 0 || written >= (int)(strlen(buf) - pos)) {
        break;
      }
    }
  }

  return buf;
}

bool check_credentials(const char *username, const char *password) {
  if (!username || !password)
    return false;

  for (int i = 0; i < user_count; i++) {
    if (users[i].is_active && strcmp(users[i].username, username) == 0 &&
        strcmp(users[i].password, password) == 0) {
      return true;
    }
  }
  return false;
}

mng_cmd parse_command(const char *line, char *arg) {
  arg[0] = '\0';
  if (!line)
    return UNKNOWN;

  char copy[256];
  strncpy(copy, line, sizeof(copy) - 1);
  copy[sizeof(copy) - 1] = '\0';

  char *saveptr;
  char *cmd = strtok_r(copy, " \r\n", &saveptr);
  if (!cmd)
    return UNKNOWN;

  if (strcasecmp(cmd, "AUTH") == 0) {
    char *cred = strtok_r(NULL, " \r\n", &saveptr);
    if (!cred)
      return UNKNOWN;
    strncpy(arg, cred, 127);
    return AUTH;
  }

  if (strcasecmp(cmd, "METRICS") == 0)
    return METRICS;

  if (strcasecmp(cmd, "ADD_USER") == 0) {
    char *cred = strtok_r(NULL, " \r\n", &saveptr);
    if (!cred)
      return UNKNOWN;
    strncpy(arg, cred, 127);
    return ADD_USER;
  }

  if (strcasecmp(cmd, "DEL_USER") == 0) {
    char *username = strtok_r(NULL, " \r\n", &saveptr);
    if (!username)
      return UNKNOWN;
    strncpy(arg, username, 127);
    return DEL_USER;
  }

  if (strcasecmp(cmd, "LIST_USERS") == 0)
    return LIST_USERS;

  if (strcasecmp(cmd, "SHOW_LOGS") == 0)
    return SHOW_LOGS;

  if (strcasecmp(cmd, "SET_BUFFER") == 0) {
    char *size = strtok_r(NULL, " \r\n", &saveptr);
    if (!size)
      return UNKNOWN;
    strncpy(arg, size, 127);
    return SET_BUFFER;
  }

  if (strcasecmp(cmd, "QUIT") == 0)
    return QUIT;

  return UNKNOWN;
}
