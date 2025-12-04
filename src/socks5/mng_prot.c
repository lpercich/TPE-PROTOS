#include "mng_prot.h"
#include "selector.h"
#include "stm.h"
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include "mng_auth.h"
#include "mng_users.h"
#include <stdio.h>

static unsigned mng_auth_read(struct selector_key *key);
static unsigned mng_auth_write(struct selector_key *key);
static unsigned mng_cmd_read(struct selector_key *key);
static unsigned mng_cmd_write(struct selector_key *key);
static unsigned mng_close_connection(struct selector_key *key);
static unsigned mng_close_connection_error(struct selector_key *key);
void reply_error(struct selector_key *key, char * msj);

static const struct state_definition metp_states[] = {
    [MNG_AUTH] ={
        .state          = MNG_AUTH,
        .on_read_ready  = mng_auth_read,
    },
    [MNG_AUTH_REPLY] ={
        .state          = MNG_AUTH_REPLY,
        .on_write_ready  = mng_auth_write,
    },
    [MNG_CMD_READ] = {
        .state          = MNG_CMD_READ,
        .on_read_ready  = mng_cmd_read,
    },
    [MNG_CMD_WRITE] = {
        .state          = MNG_CMD_WRITE,
        .on_write_ready = mng_cmd_write,
    },
    [MNG_DONE] = {
        .state          = MNG_DONE,
        .on_read_ready  = mng_close_connection,
    },
    [MNG_ERROR] = {
        .state          = MNG_ERROR,
        .on_write_ready = mng_close_connection_error,
    }
};

static bool validate_credentials(metrics_t *m) {
  for (int i = 0; i < m->user_count; i++) {
    if (m->users[i].username == NULL)
      break; // Fin de la lista

    if (strcmp(m->credentials.username, m->users[i].username) == 0 &&
        strcmp(m->credentials.password, m->users[i].password) == 0) {
      return true;
    }
  }
  return false;
}
static unsigned mng_auth_read(struct selector_key *key) {
    metrics_t * m= key->data;
    bool errored = false;
    size_t nbyte;
    uint8_t *ptr = buffer_write_ptr(&m->read_buffer, &nbyte);
    ssize_t ret = recv(key->fd, ptr, nbyte, 0);
    if (ret <= 0) return MNG_ERROR;
    buffer_write_adv(&m->read_buffer, ret);
    //Parseamos
    mng_auth_state st = mng_auth_consume(&m->read_buffer, &m->mng_auth_parser, &errored);
    if(errored) return MNG_ERROR;
    if (st == AUTH_CMD_DONE) {
        return MNG_AUTH_REPLY;
    }
    return MNG_AUTH;
}

static unsigned mng_auth_write(struct selector_key *key) {
    metrics_t *m = key->data;


    const char *response;

    if (m->cmd != AUTH) {
        response = "-ERR unknown command\r\n";
        send(key->fd, response, strlen(response), MSG_NOSIGNAL);
        return MNG_AUTH;
    }
    
    char *username = NULL;
    char *password = NULL;
    
    parse_user(m->arg, &username, &password);
    size_t user_length = username ? strlen(username) : 0;
    size_t password_length = password ? strlen(password) : 0;

    
    if (username == NULL || password == NULL) {
        response = "-ERR invalid AUTH format, expected AUTH user:pass\r\n";
        send(key->fd, response, strlen(response), MSG_NOSIGNAL);
    
        free(username);
        free(password);
         
        return MNG_AUTH;
    }

    // Copiar credenciales a la estructura
    memset(m->credentials.username, 0, sizeof(m->credentials.username));
    memset(m->credentials.password, 0, sizeof(m->credentials.password));

    strncpy(m->credentials.username, username, sizeof(m->credentials.username) - 1);
    strncpy(m->credentials.password, password, sizeof(m->credentials.password) - 1);

    free(username);
    free(password);

    m->auth_success = validate_credentials(m);

    if (m->auth_success) {
        response = "+OK authentication successful\r\n";
        send(key->fd, response, strlen(response), MSG_NOSIGNAL);
        return MNG_CMD_READ;  
    } else {
        response = "-ERR invalid credentials\r\n";
        send(key->fd, response, strlen(response), MSG_NOSIGNAL);
        return MNG_AUTH;  // Permitimos reintentar
    }
}


static unsigned mng_cmd_read(struct selector_key *key) {
    metrics_t* m= key->data;
    size_t len;
    unsigned state = MNG_ERROR;

    uint8_t *ptr = buffer_write_ptr(&m->read_buffer, &len);
    ssize_t n = recv(m->fd, ptr, len, 0); 

    if(n<0){
        reply_error(key, "management recv failed\n");
        return MNG_ERROR; 
    }

    if(n==0){
        selector_set_interest_key(key, OP_WRITE);
        return MNG_CMD_WRITE; //o done ¿?
    }

    char line[BUFFER_SIZE] = {0};
    size_t i = 0;

    while (i < len && i < sizeof(line) - 1) {
        line[i] = ptr[i];
        if (line[i] == '\n') break;
        i++;
    }

    if (i == len || line[i] != '\n') {
        return MNG_CMD_READ;  //no terminamos, seguimos leyedno
    }
    
    buffer_write_adv(&m->read_buffer, n);
    
    line[strcspn(line, "\r\n")] = '\0';
    m->cmd = parse_command(line , m->arg);
    switch(m->cmd){
        case AUTH: 
            return MNG_AUTH;
        case METRICS: {
            uint8_t * out = write_metrics();
            len= strlen(out)+1;
            buffer_write_adv(out, len);
        }
        case ADD_USER: {
            char *username = NULL;
            char *password = NULL;
            parse_user(m->arg, &username, &password);
            if (!username || !password) {
                reply_error(key, "-ERR expected USER:PASS format\r\n");
                free(username);
                free(password);
                return MNG_CMD_READ;
            }

            if (!add_user(username, password)) {
                char tmp[BUFFER_SIZE];
                snprintf(tmp, sizeof(tmp), "-ERR user %s already exists\r\n", username);
                reply_error(key, tmp);
            } else {
                char tmp[BUFFER_SIZE];
                snprintf(tmp, sizeof(tmp), "+OK user %s added successfully\r\n", username);
                send(m->fd, tmp, strlen(tmp), MSG_NOSIGNAL);
            }
            free(username);
            free(password);
            return MNG_CMD_READ;
        }

        case DEL_USER: {
            if (m->arg == NULL || strlen(m->arg) == 0) {
                reply_error(key, "-ERR missing username\r\n");
                return MNG_CMD_READ;
            }
            if (!del_user(m->arg)) {
                char tmp[BUFFER_SIZE];
                snprintf(tmp, sizeof(tmp), "-ERR user %s does not exist\r\n", m->arg);
                reply_error(key, tmp);
            } else {
            char tmp[BUFFER_SIZE];
            snprintf(tmp, sizeof(tmp), "+OK user %s deleted\r\n", m->arg);
            send(m->fd, tmp, strlen(tmp), MSG_NOSIGNAL);
        }
        return MNG_CMD_READ;
        }

        case LIST_USERS: {
            char *list = list_users();
            if (!list) {
                reply_error(key, "-ERR could not obtain user list\r\n");
                return MNG_CMD_READ;
            }
            size_t len = strlen(list);
            uint8_t *dst;
            size_t space;
            dst = buffer_write_ptr(&m->write_buffer, &space);
            if (space < len) {
                free(list);
                reply_error(key, "-ERR buffer too small\r\n");
                return MNG_ERROR;
            }
            memcpy(dst, list, len);
            buffer_write_adv(&m->write_buffer, len);
            free(list);
            return MNG_CMD_WRITE;
        }

        default:
        return MNG_ERROR;
        
    
    }

}

static unsigned mng_cmd_write(struct selector_key *key) {
    metrics_t* m= key->data;
    size_t count;
    uint8_t * out = buffer_read_ptr(&m->write_buffer, &count);
    if (count > 0) {
        ssize_t w = send(m->fd, out, count, 0);
        if (w < 0) {
            return MNG_ERROR;
        }
        buffer_read_adv(&m->write_buffer, w);
}
}
static unsigned mng_close_connection(struct selector_key *key) {
    
}

static unsigned mng_close_connection_error(struct selector_key *key) {
    metrics_t* m= key->data;
    size_t count;
    uint8_t * out = buffer_read_ptr(&m->write_buffer, &count);
    if (count > 0) {
        ssize_t w = send(m->fd, out, count, 0);
    }
    //esto quiza lo paso a done ¿?
    selector_unregister_fd(key->s, m->fd);
    close(m->fd);
    return MNG_DONE;
}

void reply_error(struct selector_key *key, char * msg){
    metrics_t* m= key->data;
    if(m==NULL) return;
    size_t count;
    uint8_t *out = buffer_write_ptr(&m->write_buffer, &count);
    size_t len = strlen(msg);
    if (len > count) len = count;
    memcpy(out, msg, len);
    buffer_write_adv(&m->write_buffer, len);
    selector_set_interest_key(key, OP_WRITE);
}

