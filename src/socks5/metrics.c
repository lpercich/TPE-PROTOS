#include "include/metrics.h"

static uint64_t historic_connections;
static uint64_t current_connections; 
static uint64_t transferred_bytes;



void init_metrics() {
    historic_connections = 0;
    current_connections = 0;
    transferred_bytes = 0;
}

uint64_t get_historic_connections(){
    return historic_connections;
}

uint64_t get_current_connections(){
    return current_connections;
}

uint64_t get_transferred_bytes(){
    return transferred_bytes;
}

void start_connection() {
    //agrgar máximo de conexiones ~ conexiones concurrentes ?
    historic_connections++;
    current_connections++;
}

void end_connection() {
    current_connections--;
}

void transfer_bytes(uint64_t bytes) {
    transferred_bytes += bytes;
}

