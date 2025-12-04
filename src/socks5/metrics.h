#ifndef METRICS_H
#define METRICS_H



typedef enum {
   AUTH,
   METRICS, //todo (historic, current, transferred)
   ADD_USER, 
   DEL_USER,
   LIST_USERS,
   QUIT,
   UNKNOWN
} mng_cmd;

void init_metrics();
uint64_t get_historic_connections();
uint64_t get_current_connections();
uint64_t get_transferred_bytes();
void start_connection();
void end_connection();
void transfer_bytes(uint64_t bytes);

#endif