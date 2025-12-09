#include "mng_prot.h"
#include "logger.h"
#include "mng_auth.h"
#include "mng_users.h"
#include "selector.h"
#include "stm.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static unsigned mng_auth_read(struct selector_key *key);
static unsigned mng_auth_write(struct selector_key *key);
static unsigned mng_cmd_read(struct selector_key *key);
static unsigned mng_cmd_write(struct selector_key *key);
static unsigned mng_close_connection(struct selector_key *key);
static unsigned mng_close_connection_error(struct selector_key *key);
void send_reply(struct selector_key *key, const char *msj);

static const struct state_definition metp_states[] = {
    [MNG_AUTH] =
        {
            .state = MNG_AUTH,
            .on_read_ready = mng_auth_read,
        },
    [MNG_AUTH_REPLY] =
        {
            .state = MNG_AUTH_REPLY,
            .on_write_ready = mng_auth_write,
        },
    [MNG_CMD_READ] =
        {
            .state = MNG_CMD_READ,
            .on_read_ready = mng_cmd_read,
        },
    [MNG_CMD_WRITE] =
        {
            .state = MNG_CMD_WRITE,
            .on_write_ready = mng_cmd_write,
        },
    [MNG_DONE] =
        {
            .state = MNG_DONE,
            .on_read_ready = mng_close_connection,
        },
    [MNG_ERROR] = {
        .state = MNG_ERROR,
        .on_write_ready = mng_close_connection_error,
    }};

static void mng_read(struct selector_key *key);
static void mng_write(struct selector_key *key);
static void mng_close(struct selector_key *key);

static const struct fd_handler mng_handler = {
    .handle_read = mng_read,
    .handle_write = mng_write,
    .handle_close = mng_close,
};

static void mng_read(struct selector_key *key) {
  metrics_t *m = key->data;
  unsigned state = stm_handler_read(&m->stm, key);
  if (state == MNG_ERROR || state == MNG_DONE) {
    selector_unregister_fd(key->s, key->fd);
  }
}

static void mng_write(struct selector_key *key) {
  metrics_t *m = key->data;
  unsigned state = stm_handler_write(&m->stm, key);
  if (state == MNG_ERROR || state == MNG_DONE) {
    selector_unregister_fd(key->s, key->fd);
  }
}

static void mng_close(struct selector_key *key) {
  metrics_t *m = key->data;
  if (m == NULL)
    return;

  // selector_unregister_fd calls this, so we don't call it back.
  // We just close the fd and free memory.
  if (key->fd != -1) {
    close(key->fd);
  }
  free(m);
  key->data = NULL;
}

void mng_passive_accept(struct selector_key *key) {
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  metrics_t *state = NULL;

  const int client =
      accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
  if (client == -1) {
    return;
  }

  if (selector_fd_set_nio(client) == -1) {
    goto fail;
  }

  state = malloc(sizeof(metrics_t));
  if (state == NULL) {
    goto fail;
  }
  memset(state, 0, sizeof(*state));
  state->fd = client;

  buffer_init(&state->read_buffer, sizeof(state->raw_buff_read),
              state->raw_buff_read);
  buffer_init(&state->write_buffer, sizeof(state->raw_buff_write),
              state->raw_buff_write);

  state->mng_auth_parser.state = AUTH_CMD_START;

  state->stm.initial = MNG_AUTH;
  state->stm.max_state = MNG_ERROR;
  state->stm.states = metp_states;
  state->stm.current = NULL;
  stm_init(&state->stm);

  if (selector_register(key->s, client, &mng_handler, OP_READ, state) !=
      SELECTOR_SUCCESS) {
    goto fail;
  }
  return;

fail:
  if (client != -1) {
    close(client);
  }
  if (state != NULL) {
    free(state);
  }
}

static unsigned mng_auth_read(struct selector_key *key) {
  metrics_t *m = key->data;
  bool errored = false;
  size_t nbyte;
  uint8_t *ptr = buffer_write_ptr(&m->read_buffer, &nbyte);
  ssize_t ret = recv(key->fd, ptr, nbyte, 0);

  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return MNG_AUTH;
    }
    send_reply(key, "-ERR unexpected read error\n\r");
    return MNG_ERROR;
  }

  if (ret == 0)
    return MNG_DONE;

  printf("MNG Read: %zd bytes\n", ret);
  buffer_write_adv(&m->read_buffer, ret);
  // Parseamos
  mng_auth_state st =
      mng_auth_consume(&m->read_buffer, &m->mng_auth_parser, &errored);
  if (errored) {
    send_reply(key, "-ERR command too long\n\r");
    return MNG_ERROR;
  }
  if (st == AUTH_CMD_DONE) {
    m->cmd = parse_command(m->mng_auth_parser.buffer, m->arg);

    const char *response;
    if (m->cmd != AUTH) {
      m->auth_success = false;
      send_reply(key, "-ERR unknown command\r\n");
    } else {
      char *username = NULL;
      char *password = NULL;
      parse_user(m->arg, &username, &password);

      if (username == NULL || password == NULL) {
        send_reply(
            key, "-ERR invalid AUTH format, expected: AUTH user:password\r\n");
        if (username)
          free(username);
        if (password)
          free(password);

        // Reset parser
        m->mng_auth_parser.state = AUTH_CMD_START;
        buffer_reset(&m->read_buffer);
        m->auth_success = false;
      } else {
        // Check credentials
        memset(m->credentials.username, 0, sizeof(m->credentials.username));
        memset(m->credentials.password, 0, sizeof(m->credentials.password));
        strncpy(m->credentials.username, username,
                sizeof(m->credentials.username) - 1);
        strncpy(m->credentials.password, password,
                sizeof(m->credentials.password) - 1);
        free(username);
        free(password);

        m->auth_success =
            check_credentials(m->credentials.username, m->credentials.password);

        if (m->auth_success) {
          response = "+OK authentication successful\r\n";
        } else {
          response = "-ERR invalid credentials\r\n";
          // Reset parser
          m->mng_auth_parser.state = AUTH_CMD_START;
          buffer_reset(&m->read_buffer);
        }
        send_reply(key, response);
      }
      selector_set_interest_key(key, OP_WRITE);
    }
    return MNG_AUTH_REPLY;
  }
  return MNG_AUTH;
}

static unsigned mng_auth_write(struct selector_key *key) {
  metrics_t *m = key->data;
  size_t count;
  uint8_t *out = buffer_read_ptr(&m->write_buffer, &count);

  if (count > 0) {
    ssize_t w = send(m->fd, out, count, MSG_NOSIGNAL);
    if (w < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return MNG_AUTH_REPLY;
      }
      return MNG_ERROR;
    }
    buffer_read_adv(&m->write_buffer, w);
  }

  if (!buffer_can_read(&m->write_buffer)) {
    if (m->auth_success) {
      selector_set_interest_key(key, OP_READ);
      buffer_reset(&m->read_buffer);
      return MNG_CMD_READ;
    } else {
      selector_set_interest_key(key, OP_READ);
      return MNG_AUTH;
    }
  }

  return MNG_AUTH_REPLY;
}

static unsigned mng_cmd_read(struct selector_key *key) {
  metrics_t *m = key->data;
  size_t len;

  uint8_t *ptr = buffer_write_ptr(&m->read_buffer, &len);
  ssize_t n = recv(m->fd, ptr, len, 0);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return MNG_CMD_READ;
    }
    return MNG_ERROR;
  }

  if (n == 0) {
    return MNG_DONE;
  }

  char line[BUFFER_SIZE] = {0};
  size_t i = 0;

  buffer_write_adv(&m->read_buffer, n);

  size_t read_len;
  uint8_t *read_ptr = buffer_read_ptr(&m->read_buffer, &read_len);
  bool found_newline = false;

  i = 0;
  while (i < read_len && i < BUFFER_SIZE - 1) {
    line[i] = read_ptr[i];
    if (line[i] == '\n') {
      line[i + 1] = '\0';
      found_newline = true;
      buffer_read_adv(&m->read_buffer, i + 1);
      break;
    }
    i++;
  }

  if (!found_newline) {
    if (read_len >= BUFFER_SIZE - 1) {
      send_reply(key, "-ERR line too long\r\n");
      buffer_reset(&m->read_buffer);
    }
    return MNG_CMD_READ;
  }

  line[strcspn(line, "\r\n")] = '\0';
  m->cmd = parse_command(line, m->arg);

  switch (m->cmd) {
  case AUTH:
    send_reply(key, "-ERR already authenticated\r\n");
    return MNG_CMD_WRITE;

  case METRICS: {
    uint8_t *out = write_metrics();
    size_t len = strlen((char *)out);
    size_t space;
    uint8_t *dst = buffer_write_ptr(&m->write_buffer, &space);
    if (space >= len) {
      memcpy(dst, out, len);
      buffer_write_adv(&m->write_buffer, len);
      free(out);
      selector_set_interest_key(key, OP_WRITE);
      return MNG_CMD_WRITE;
    } else {
      free(out);
      return MNG_ERROR;
    }
  }
  case ADD_USER: {
    char *username = NULL;
    char *password = NULL;
    parse_user(m->arg, &username, &password);
    if (!username || !password) {
      send_reply(key, "-ERR invalid format, expected format USER:PASSWORD\r\n");
      if (username)
        free(username);
      if (password)
        free(password);
      return MNG_CMD_WRITE;
    }

    if (!add_user(username, password)) {
      char tmp[BUFFER_SIZE];
      snprintf(tmp, sizeof(tmp), "-ERR user %s already exist\r\n", username);
      send_reply(key, tmp);
    } else {
      char tmp[BUFFER_SIZE];
      snprintf(tmp, sizeof(tmp), "+OK user %s added correctly\r\n", username);
      send_reply(key, tmp);
    }
    free(username);
    free(password);
    return MNG_CMD_WRITE;
  }

  case DEL_USER: {
    if (strlen(m->arg) == 0) {
      send_reply(key, "-ERR user missing\r\n");
      return MNG_CMD_WRITE;
    }
    if (!del_user(m->arg)) {
      char tmp[BUFFER_SIZE];
      snprintf(tmp, sizeof(tmp), "-ERR user %s does not exist\r\n", m->arg);
      send_reply(key, tmp);
    } else {
      char tmp[BUFFER_SIZE];
      snprintf(tmp, sizeof(tmp), "+OK user %s deleted\r\n", m->arg);
      send_reply(key, tmp);
    }
    return MNG_CMD_WRITE;
  }

  case LIST_USERS: {
    char *list = list_users();
    if (!list) {
      send_reply(key, "-ERR could not retrieve user list\r\n");
      return MNG_CMD_WRITE;
    }
    size_t len = strlen(list);
    uint8_t *dst;
    size_t space;
    dst = buffer_write_ptr(&m->write_buffer, &space);
    if (space < len) {
      free(list);
      send_reply(key, "-ERR buffer too small\r\n");
      return MNG_CMD_WRITE;
    }
    memcpy(dst, list, len);
    buffer_write_adv(&m->write_buffer, len);
    // free(list); // list is static buffer, do not free
    selector_set_interest_key(key, OP_WRITE);
    return MNG_CMD_WRITE;
  }

  case SHOW_LOGS: {
    char *logs = read_access_logs();
    if (!logs) {
      send_reply(key, "-ERR could not get logs\r\n");
      return MNG_CMD_WRITE;
    }

    char header[] = "+OK\r\n";
    char truncated_header[] = "+OK (truncated, showing most recent logs)\r\n";
    size_t logs_len = strlen(logs);

    uint8_t *dst;
    size_t space;
    dst = buffer_write_ptr(&m->write_buffer, &space);

    size_t header_len = strlen(header);
    size_t total_len = header_len + logs_len;

    if (space >= total_len) {
      // Los logs caben completos
      memcpy(dst, header, header_len);
      memcpy(dst + header_len, logs, logs_len);
      buffer_write_adv(&m->write_buffer, total_len);
    } else {
      // No caben todos: mostrar los más recientes
      size_t trunc_header_len = strlen(truncated_header);
      size_t available_for_logs = space - trunc_header_len;

      if (available_for_logs > 0 && logs_len > 0) {
        // Calcular offset para mostrar solo la parte final de los logs
        size_t offset =
            logs_len > available_for_logs ? logs_len - available_for_logs : 0;
        size_t logs_to_send = logs_len - offset;

        memcpy(dst, truncated_header, trunc_header_len);
        memcpy(dst + trunc_header_len, logs + offset, logs_to_send);
        buffer_write_adv(&m->write_buffer, trunc_header_len + logs_to_send);
      } else {
        // No hay espacio para nada útil
        free(logs);
        send_reply(key, "-ERR buffer too small\r\n");
        return MNG_CMD_WRITE;
      }
    }

    free(logs);
    selector_set_interest_key(key, OP_WRITE);
    return MNG_CMD_WRITE;
  }

  case SET_BUFFER: {

    int size = atoi(m->arg);
    if (size <= 0 || size > 65535) {
      send_reply(key, "-ERR invalid size (accepted sizes: 1-65535)\r\n");
      return MNG_CMD_WRITE;
    }

    extern void configure_buffer_size(size_t size);
    configure_buffer_size((size_t)size);

    char tmp[BUFFER_SIZE];
    snprintf(tmp, sizeof(tmp), "+OK buffer size changed to %d\r\n", size);
    send_reply(key, tmp);
    return MNG_CMD_WRITE;
  }

  case QUIT:
    return MNG_DONE;

  default:
    send_reply(key, "-ERR unknown command\r\n");
    return MNG_CMD_WRITE;
  }
}

static unsigned mng_cmd_write(struct selector_key *key) {
  metrics_t *m = key->data;
  size_t count;
  uint8_t *out = buffer_read_ptr(&m->write_buffer, &count);
  if (count > 0) {
    ssize_t w = send(m->fd, out, count, MSG_NOSIGNAL);
    if (w < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return MNG_CMD_WRITE;
      }
      return MNG_ERROR;
    }
    buffer_read_adv(&m->write_buffer, w);
  }

  if (!buffer_can_read(&m->write_buffer)) {
    selector_set_interest_key(key, OP_READ);
    return MNG_CMD_READ;
  }

  return MNG_CMD_WRITE;
}

static unsigned mng_close_connection(struct selector_key *key) {
  (void)key;
  return MNG_DONE;
}

static unsigned mng_close_connection_error(struct selector_key *key) {
  metrics_t *m = key->data;
  size_t count;
  uint8_t *out = buffer_read_ptr(&m->write_buffer, &count);
  if (count > 0) {
    ssize_t w;
    while (count > 0) {
      w = send(m->fd, out, count, MSG_NOSIGNAL);
      if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        break;
      }
      buffer_read_adv(&m->write_buffer, w);
      out = buffer_read_ptr(&m->write_buffer, &count);
    }
  }
  selector_unregister_fd(key->s, m->fd);

  return MNG_DONE;
}

void send_reply(struct selector_key *key, const char *msg) {
  metrics_t *m = key->data;
  if (m == NULL)
    return;
  size_t count;
  uint8_t *out = buffer_write_ptr(&m->write_buffer, &count);
  size_t len = strlen(msg);
  if (len > count)
    len = count;
  memcpy(out, msg, len);
  buffer_write_adv(&m->write_buffer, len);
  selector_set_interest_key(key, OP_WRITE);
}
