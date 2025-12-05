# Protocolo de Gestión (MNG)

Este documento define el protocolo de gestión basado en texto para el servidor proxy SOCKSv5. El protocolo corre en un puerto TCP dedicado (por defecto 8080) y permite a los administradores monitorear métricas y gestionar usuarios.

## Formato General

- **Transporte**: TCP
- **Codificación**: ASCII / UTF-8
- **Terminador de Línea**: `\n` (LF)
- **Estructura**: Petición-Respuesta. El servidor procesa un comando a la vez por conexión.

## Comandos

### 1. METRICS

Obtiene las métricas actuales del servidor.

**Petición:**
```
METRICS\n
```

**Respuesta:**
```
+OK metricas\r\n
conexiones_totales: <entero>\r\n
conexiones_actuales: <entero>\r\n
bytes_transferidos: <entero>\r\n
```

**Ejemplo:**
```
METRICS
+OK metricas
conexiones_totales: 5
conexiones_actuales: 1
bytes_transferidos: 102400
```

### 2. ADD_USER

Agrega un nuevo usuario para la autenticación SOCKSv5.

**Petición:**
```
ADD_USER <usuario>:<contraseña>\n
```

**Respuesta:**
- Éxito: `+OK usuario <usuario> agregado exitosamente\r\n`
- Fallo (Usuario existe): `-ERR usuario <usuario> ya existe\r\n`
- Fallo (Error de formato): `-ERR formato esperado USUARIO:CLAVE\r\n`

**Ejemplo:**
```
ADD_USER admin:secreto123
+OK usuario admin agregado exitosamente
```

### 3. DEL_USER

Elimina un usuario existente.

**Petición:**
```
DEL_USER <usuario>\n
```

**Respuesta:**
- Éxito: `+OK usuario <usuario> eliminado\r\n`
- Fallo (Usuario no encontrado): `-ERR usuario <usuario> no existe\r\n`
- Fallo (Falta argumento): `-ERR falta usuario\r\n`

**Ejemplo:**
```
DEL_USER admin
+OK usuario admin eliminado
```

### 4. LIST_USERS

Lista todos los usuarios registrados.

**Petición:**
```
LIST_USERS\n
```

**Respuesta:**
```
+OK <usuario1> <usuario2> ...\r\n
```

### 5. SHOW_LOGS

Devuelve los últimos registros de acceso (conexiones exitosas y fallidas).

**Petición:**
```
SHOW_LOGS\n
```

**Respuesta:**
```
+OK\r\n
[TIMESTAMP] user=... src=... dst=... status=...\n
...
```

### 6. SET_BUFFER

Cambia el tamaño del buffer de lectura/escritura para las nuevas conexiones SOCKS5.

**Petición:**
```
SET_BUFFER <bytes>\n
```

**Respuesta:**
- Éxito: `+OK buffer size cambiado a <bytes>\r\n`
- Fallo: `-ERR tamaño invalido\r\n`

### 7. QUIT

Cierra la conexión de administración.

**Petición:**
```
QUIT\n
```

## Autenticación

Al conectarse, el cliente debe autenticarse.

**Petición:**
```
AUTH <usuario>:<contraseña>\n
```

**Respuesta:**
- Éxito: `+OK autenticacion exitosa\r\n`
- Fallo: `-ERR credenciales invalidas\r\n`
- Fallo (Formato): `-ERR formato AUTH invalido, se espera AUTH usuario:clave\r\n`

## Manejo de Errores

Si se recibe un comando desconocido:
```
-ERR comando desconocido\r\n
```
