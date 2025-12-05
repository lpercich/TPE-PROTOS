#ifndef LOGGER_H
#define LOGGER_H

/**
 * Registra un acceso en el log.
 *
 * @param user Usuario autenticado (o "anonymous" si no aplica)
 * @param src_addr Dirección IP y puerto de origen (cliente)
 * @param dst_addr Dirección IP y puerto de destino (servidor remoto)
 * @param status Estado de la conexión (ej: "CONNECT", "FAIL", "BLOCK")
 */
void log_access(const char *user, const char *src_addr, const char *dst_addr,
                const char *status);

/**
 * Devuelve un string con todos los logs acumulados.
 * El caller es responsable de liberar la memoria (free).
 */
char *read_access_logs(void);

#endif
