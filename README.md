# Servidor Proxy SOCKSv5

Este proyecto implementa un **Servidor Proxy SOCKSv5** (RFC 1928) concurrente y no bloqueante, desarrollado en C para la materia **Protocolos de Comunicación (ITBA 2025)**.

Soporta:
*   Protocolo SOCKSv5 completo
*   Autenticación por Usuario/Contraseña (RFC 1929).
*   Resolución de nombres asincrónica (sin bloquear el selector principal).
*   Soporte híbrido IPv4 e IPv6.
*   **Protocolo de Gestión (MNG)** para monitoreo en tiempo real y configuración dinámica.

---

## � Integrantes

*   Santiago Diaz Sieiro
*   Lucila Borinsky
*   Luana Percich
*   Catalina Trajterman

---

## 🛠 Requisitos e Instalación


### Instrucciones

1.  **Clonar el repositorio**:
    ```bash
    git clone https://github.com/TPE-PROTOS-2025/TPE-PROTOS.git
    cd TPE-PROTOS
    ```

2.  **Limpiar compilación previa**:
    ```bash
    make clean
    ```

3.  **Compilar el proyecto**:
    ```bash
    make all
    ```
    Se generarán los binarios `socks5d` (servidor) y `client` (cliente de gestión).

---

## 🚀 Ejecución del Servidor

El servidor se ejecuta mediante el binario `socks5d`. Por defecto escucha en `::` (todas las interfaces IPv4/IPv6) puerto `1080`.

### Sintaxis
```bash
./socks5d [OPCIONES]
```

### Argumentos Disponibles

*   `-h`: Imprime la ayuda y termina.
*   `-l <SOCKS addr>`: Dirección IP donde servirá el proxy SOCKS. Por defecto: `::`.
*   `-p <SOCKS port>`: Puerto TCP para conexiones SOCKS. Por defecto: `1080`.
*   `-L <mng addr>`: Dirección IP para el protocolo de gestión. Por defecto: `127.0.0.1`.
*   `-P <mng port>`: Puerto TCP para gestión. Por defecto: `8080`.
*   `-u <name>:<pass>`: Registra un usuario para SOCKSv5. Se pueden agregar hasta 10.
*   `-v`: Imprime la versión del programa.


### Ejemplos

**Básico (Sin autenticación):**
```bash
./socks5d
```

**Con usuario SOCKS y puerto específico:**
```bash
./socks5d -p 8888 -u admin:secret123
```

**Con múltiples usuarios y escuchando en localhost:**
```bash
./socks5d -l 127.0.0.1 -u juan:1234 -u maria:5678
```

---

## 🔧 Protocolo de Gestión

El sistema incluye un protocolo de gestión texto-plano que permite monitorear el servidor sin detenerlo.

### Conectarse al administrador
Se recomienda usar la herramienta `client` provista:
```bash
./client 127.0.0.1 8080
```

### Comandos de Gestión
Una vez conectado, autenticarse con el usuario administrador (default: `admin`/`secret` o variable de entorno `ADMIN_PASS`).

1.  **Autenticación**: `USER admin` -> `PASS secret`.
2.  **Métricas**: `METRICS`.
3.  **Usuarios**: `LIST_USERS`, `ADD_USER <u:p>`, `DEL_USER <user>`.
4.  **Configuración**: `SET_BUFFER <bytes>`

---

## 🧪 Testing y Monitoreo

El proyecto incluye una suite de pruebas automatizada:
```bash
./test_suite.sh
```
Esto ejecuta pruebas de conexión, concurrencia (stress test), descarga de archivos grandes y verifica memory leaks.

