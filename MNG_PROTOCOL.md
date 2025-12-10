# Protocolo de Gestión

Este documento especifica el protocolo de gestión basado en texto para el servidor proxy SOCKSv5. El protocolo permite a los administradores autenticarse, gestionar usuarios y monitorear métricas en tiempo real.

**Conexión por Defecto:** Puerto 8080 (TCP).

---

## 1. Autenticación

En caso de querer conectarse al servicio de management via netcat (`nc localhost 8080`), la autenticación es el primer paso obligatorio.

**Comando:**
```text
AUTH <user>:<pass>
```

**Respuesta Exitosa:**
```text
+OK authentication successful
```

**Respuesta de Error:**
```text
-ERR invalid credentials
```

---

## 2. Ejecución de Comandos

Tras una autenticación exitosa, el servidor queda a la espera de instrucciones.

### Alta de Usuarios
Permite registrar nuevos usuarios para el uso del proxy SOCKS5 en tiempo de ejecución.

**Comando:**
```text
ADD_USER <usuario>:<contraseña>
```

**Ejemplo:**
```text
ADD_USER michael:scott
```

**Respuestas:**
*   Éxito: `+OK user michael added correctly`
*   Error: `-ERR user <name> already exist`

### Baja de Usuarios
Permite eliminar usuarios existentes para el uso del proxy SOCKS5 en tiempo de ejecución.

**Comando:**
```text
DEL_USER <user>
```

**Respuestas:**
*   Éxito: `+OK user <user> deleted`
*   Error: `-ERR user <name> does not exist`

### Listado de Usuarios
Devuelve la lista completa de usuarios actualmente activos en el sistema.

**Comando:**
```text
LIST_USERS
```

**Salida:**
Lista de nombres de usuario separados por espacios o saltos de línea.

### Consulta de Métricas
Permite visualizar en tiempo real las estadísticas vitales del servidor.

**Comando:**
```text
METRICS
```

**Formato de Salida:**
```text
+OK metrics
total connections: <num>
current connections: <num>
total transferred bytes: <num>
```

### Consulta de Logs
Solicita al servidor el registro de accesos.

**Comando:**
```text
SHOW_LOGS
```

**Formato de Salida:**
```text
[Fecha] user=<u_proxy> src=<ip_origen> dst=<destino>
```

### Configuración Avanzada (Buffer)
Permite modificar en tiempo de ejecución el tamaño del buffer de lectura/escritura (rango válido: 1 a 65535 bytes).

**Comando:**
```text
SET_BUFFER <bytes>
```

**Ejemplo:**
```text
SET_BUFFER 4096
```

**Respuesta:**
```text
+OK buffer size changed to 4096
```

### Finalización de Sesión
Cierra ordenadamente la conexión.

**Comando:**
```text
QUIT
```

---

## 3. Manejo de Errores

El protocolo es explícito en sus respuestas de error, facilitando la depuración. Todos los errores comienzan con `-ERR`.

**Listado de Errores Implementados:**

*   `-ERR unexpected read error`: Error en la lectura del socket (`recv`).
*   `-ERR command too long`: Overflow del buffer de entrada.
*   `-ERR unknown command`: Instrucción no reconocida.
*   `-ERR invalid AUTH format`: El formato no es `user:pass`.
*   `-ERR invalid credentials`: Contraseña incorrecta.
*   `-ERR user <name> already exist`: Usuario ya registrado.
*   `-ERR already authenticated`: Intento de login con sesión activa.
*   `-ERR user missing`: Falta el argumento de usuario en `DEL_USER`.
*   `-ERR user <name> does not exist`: Usuario a eliminar no existe.
*   `-ERR could not retrieve user list`: Error interno al listar usuarios.
*   `-ERR invalid size (accepted sizes: 1-65535)`: Tamaño de buffer fuera de rango.

---
*Esta interfaz permite realizar tareas de mantenimiento y auditoría de manera eficiente y en tiempo real.*
