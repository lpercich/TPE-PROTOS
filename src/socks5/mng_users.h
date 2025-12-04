#ifndef MNG_USERS_H
#define MNG_USERS_H

#DEFINE MAX_USERS 500 //chequear cuantos ¿¿???

typedef struct user {
    char * username;
    char * password;
    bool is_active;
}user_t;
#endif