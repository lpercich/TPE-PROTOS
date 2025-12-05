#ifndef MNG_USERS_H
#define MNG_USERS_H
#include "metrics.h"
#include <stdbool.h>

typedef struct user {
  char *username;
  char *password;
  bool is_active;
} user_t;

bool init_users(void);
void parse_user(const char *user, char **username, char **password);
bool add_user(const char *username, const char *password);
bool del_user(char *username);
char *list_users(void);
bool check_credentials(const char *username, const char *password);
mng_cmd parse_command(const char *line, char *arg);

#endif