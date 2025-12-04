# Servidor Proxy SOCKSv5

Servidor proxy concurrente basado en eventos (no bloqueante) que implementa el protocolo SOCKSv5 (RFC 1928). Soporta autenticación de usuario/contraseña, conexión a destinos IPv4/IPv6 y resolución DNS asincrónica (DNS no terminado).

## Compilación

### Comandos

* **Compilar el proyecto:**
    ```bash
    make all
    ```
    Esto genera el ejecutable `socks5d`.

* **Limpiar archivos objeto y binarios:**
    ```bash
    make clean
    ```

## Ejecución

El servidor se ejecuta mediante el binario `socks5d`. Por defecto escucha en `0.0.0.0:1080`.

### Sintaxis

```bash
./socks5d [OPCIONES]

Argumentos Disponibles

    -h Imprime la ayuda y termina.

    -l <SOCKS addr> Dirección donde servirá el proxy SOCKS. Por defecto escucha en todas las interfaces (0.0.0.0 o ::).

    -p <SOCKS port> Puerto entrante para conexiones SOCKS. Por defecto es 1080.

    -L <conf addr> Dirección donde servirá el protocolo de gestión/monitoreo. Por defecto 127.0.0.1.

    -P <conf port> Puerto entrante para conexiones de gestión/monitoreo. Por defecto es 8080.

    -u <name>:<pass> Registra un usuario y contraseña para autenticación. Se permite hasta un máximo de 10 usuarios. Si no se especifican usuarios, el servidor permite conexiones sin autenticación (NO AUTH).

    -v Imprime información sobre la versión y termina.

    -N Deshabilita los disectors de contraseñas (funcionalidad de sniffing).

Ejemplos de Uso

    Ejecución básica (sin autenticación, puerto 1080):
    Bash

./socks5d

Ejecución con usuario y puerto específico:
Bash

./socks5d -p 8888 -u admin:secret123

Ejecución en una interfaz específica con múltiples usuarios:
Bash

./socks5d -l 127.0.0.1 -u juan:1234 -u maria:5678