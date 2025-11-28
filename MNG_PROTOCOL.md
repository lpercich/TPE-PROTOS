# Management Protocol (MNG) Specification

This document defines the text-based management protocol for the SOCKSv5 proxy server. The protocol runs on a dedicated TCP port (default 8080) and allows administrators to monitor metrics and manage users.

## General Format

- **Transport**: TCP
- **Encoding**: ASCII / UTF-8
- **Line Terminator**: `\n` (LF)
- **Structure**: Request-Response. The server processes one command at a time per connection.

## Commands

### 1. GET METRICS

Retrieves current server metrics.

**Request:**
```
GET METRICS\n
```

**Response:**
```
CONN_CURR: <integer>\n
BYTES_TRANSFERRED: <integer>\n
CONN_HIST: <integer>\n
OK\n
```

**Example:**
```
GET METRICS
CONN_CURR: 5
BYTES_TRANSFERRED: 102400
CONN_HIST: 120
OK
```

### 2. ADDUSER

Adds a new user for SOCKSv5 authentication.

**Request:**
```
ADDUSER <username>:<password>\n
```

**Response:**
- Success: `OK\n`
- Failure (User exists): `ERR_EXISTS\n`
- Failure (Max users reached): `ERR_FULL\n`

**Example:**
```
ADDUSER admin:secret123
OK
```

### 3. DELUSER

Deletes an existing user.

**Request:**
```
DELUSER <username>\n
```

**Response:**
- Success: `OK\n`
- Failure (User not found): `ERR_NOT_FOUND\n`

**Example:**
```
DELUSER admin
OK
```

### 4. LISTUSERS

Lists all configured users.

**Request:**
```
LISTUSERS\n
```

**Response:**
```
USER: <username1>\n
USER: <username2>\n
...
OK\n
```

**Example:**
```
LISTUSERS
USER: admin
USER: guest
OK
```

## Error Handling

If an unknown command is received:
```
ERR_UNKNOWN_CMD\n
```

If arguments are missing or invalid:
```
ERR_INVALID_ARGS\n
```
