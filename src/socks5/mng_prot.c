#include "mng_prot.h"

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
        .on_write_ready  = mng_auth_reply,
    }
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

static unsigned mng_auth_read(struct selector_key *key) {
    metrics_t * m= key->data;
    bool errored = false;
    size_t nbyte;
    uint8_t *ptr = buffer_write_ptr(&m->read_buffer, &nbyte);
    ssize_t ret = recv(key->fd, ptr, nbyte, 0);
    if (ret <= 0) return ERROR;
    buffer_write_adv(&m->read_buffer, ret);
    //Parseamos
    mng_auth_state st = mng_auth_consume(&m->read_buffer, &m->mng_auth_parser, &errored);
    if(errored) return ERROR;
    if (st == AUTH_CMD_DONE) {
        return MNG_AUTH_REPLY;
    }
    return MNG_AUTH;
}

static unsigned mng_auth_write(struct selector_key *key) {
    metrics_t *m = key->data;


    const char *response;

    // 1) Verificar comando
    if (m->cmd != AUTH) {
        response = "-ERR unknown command\r\n";
        send(key->fd, response, strlen(response), MSG_NOSIGNAL);
        return MNG_AUTH;
    }
    
    char *username = NULL;
    char *password = NULL;
    
    parse_user(m->arg, &username, &password);
    
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

    strncpy(m->credentials.username, m->arg, MIN(user_length, sizeof(m->credentials.username) - 1));

    strncpy(m->credentials.password, separator + 1, MIN(password_length, sizeof(m->credentials.password) - 1));
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
    unsigned state = METP_ERROR;

    uint8_t *in = buffer_write_ptr(&m->read_buffer, &len);
    ssize_t n = recv(m->fd, in, len, 0); 

    if(n<0){
        reply_error(key, "management recv failed\n");
        return ERROR; 
    }

    if(n==0){
        selector_set_interest_key(key, OP_WRITE);
        return MNG_CMD_WRITE; //o done ¿?
    }

    char line[256] = {0};
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

    char out [MAX_BUF];
    int len;
    switch(m->cmd){
        case AUTH:
        return MNG_AUTH;
        case METRICS:
        out=write_metrics(m);
        len= strlen(out)+1;
        buffer_write_adv(out, len);
        case ADD_USER:
            char *user = strtok_r(NULL, " \r\n", &saveptr);
            char *pass = strtok_r(NULL, " \r\n", &saveptr);
            if (!user || !pass) {
                reply_error(key, "-ERR user and password must be present with format USER:PASS \n");
                return ERROR;
            }
            if(!add_user(user, pass)){
                sprintf(out, "-ERR user %s already exists \n", user);
                reply_error(key, out);
                return ERROR;
            }else{
            sprintf(out, "+OK user %s added successfully \n", user);
            len= strlen(out)+1;
            buffer_write_adv(out, len);
            break;
            }
            
        case DEL_USER:
            char *user = strtok_r(NULL, " \r\n", &saveptr);
            if (!user) {
                reply_error(key, "-ERR user must be present");
                return ERROR;
            } else {
                if(!del_user(user)){
                sprintf(out, "-ERR user %s does not exist \n", user);
                reply_error(key, out);
                }else{
                sprintf(out, "+OK user %s deleted successfully \n", user);
                len= strlen(out)+1;
                buffer_write_adv(out, len);
                }
            }
            break;
        case LIST_USERS:
        char * list = list_users();
        
        //o tamaño maximo de
        for(int i=0; list[i]!='\0'; i++){
            sprintf(out, "USER: %s \n", list[i]);
            len= strlen(out)+1;
            buffer_write_adv(out, len);
        }
        break;
        case QUIT:
        return DONE; //por ahi hacerlo aca ¿?
        default:
        return ERROR;
    
    }

}

static unsigned mng_cmd_write(struct selector_key *key) {
    metrics_t* m= key->data;
   char out[MAX_BUF];
    size_t count;
    out = buffer_read_ptr(&m->write_buffer, &count);
    if (count > 0) {
        ssize_t w = send(m->fd, out, count, 0);
        if (w < 0) {
            return ERROR;
        }
        buffer_read_adv(&m->write_buffer, w);
}
}
static unsigned mng_close_connection(struct selector_key *key) {
    
}

static unsigned mng_close_connection_error(struct selector_key *key) {
    metrics_t* m= key->data;
    size_t count;
    out = buffer_read_ptr(&m->write_buffer, &count);
    if (count > 0) {
        ssize_t w = send(m->fd, out, count, 0);
    }
    //esto quiza lo paso a done ¿?
    selector_unregister_fd(key->s, m->fd);
    close(m->fd);
    return DONE;
}

void reply_error(struct selector_key *key, char * msj){
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

