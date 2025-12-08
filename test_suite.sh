#!/bin/bash

# ================= CONFIGURACIÓN =================
PROXY_BIN="./socks5d"
CLIENT_BIN="./client"
PROXY_PORT=1080
MNG_PORT=8080
USER="admin"
PASS="1234"
TARGET_URL="http://google.com/"
# =================================================

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función de limpieza
cleanup() {
    echo -e "\n${YELLOW}--- Limpiando procesos... ---${NC}"
    if [ ! -z "$PID_PROXY" ]; then kill -9 $PID_PROXY 2>/dev/null; fi
    pkill -P $$ 2>/dev/null || true
    echo -e "${GREEN}Limpieza completada.${NC}"
}
trap cleanup EXIT SIGINT

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_metric() {
    echo -e "  ${GREEN}$1:${NC} $2"
}

get_metrics() {
    $CLIENT_BIN 127.0.0.1 $MNG_PORT $USER:$PASS METRICS 2>/dev/null
}

get_historical_connections() {
    get_metrics | grep "total connections" | awk '{print $3}' | tr -d '\r'
}

get_current_connections() {
    get_metrics | grep "current connections" | awk '{print $3}' | tr -d '\r'
}

get_bytes_transferred() {
    get_metrics | grep "total transferred" | awk '{print $4}' | tr -d '\r'
}

# =================================================
# INICIO DE TESTS
# =================================================

print_header "SUITE DE PRUEBAS DE ESTRÉS - SOCKS5"
echo -e "Fecha: $(date)"
echo -e "Target: $TARGET_URL"

# 1. Compilación
print_header "1. COMPILACIÓN"
echo "Compilando proyecto..."
make clean > /dev/null 2>&1 && make all > /dev/null 2>&1
if [ ! -f "$PROXY_BIN" ] || [ ! -f "$CLIENT_BIN" ]; then
    echo -e "${RED}Error: No se generaron los binarios.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Compilación exitosa${NC}"

# 2. Levantar servidor
print_header "2. INICIANDO SERVIDOR PROXY"
$PROXY_BIN -p $PROXY_PORT -P $MNG_PORT -u $USER:$PASS > server.log 2>&1 &
PID_PROXY=$!
sleep 2

# Verificar que el servidor está corriendo
if ! kill -0 $PID_PROXY 2>/dev/null; then
    echo -e "${RED}Error: El servidor no arrancó correctamente${NC}"
    cat server.log
    exit 1
fi
echo -e "${GREEN}✓ Servidor iniciado (PID: $PID_PROXY)${NC}"

# 3. Test de conexión básica
print_header "3. TEST DE CONEXIÓN BÁSICA"
echo "Probando conexión simple..."
# Usamos example.com que siempre está disponible
BASIC_TEST_URL="http://example.com/"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 -x socks5://$USER:$PASS@127.0.0.1:$PROXY_PORT $BASIC_TEST_URL 2>/dev/null || echo "000")
# Cualquier código HTTP válido (no 000) significa que el proxy funcionó
if [[ "$HTTP_CODE" != "000" ]]; then
    echo -e "${GREEN}✓ Conexión básica exitosa (HTTP $HTTP_CODE)${NC}"
else
    echo -e "${RED}✗ Conexión básica falló (sin respuesta)${NC}"
fi

# Mostrar métricas iniciales
echo ""
echo "Métricas iniciales:"
print_metric "Conexiones históricas" "$(get_historical_connections)"
print_metric "Conexiones actuales" "$(get_current_connections)"
print_metric "Bytes transferidos" "$(get_bytes_transferred)"

# 4. Test de concurrencia masiva
print_header "4. TEST DE CONCURRENCIA MASIVA"
echo "Ejecutando 500 conexiones simultáneas..."
echo "(Esto puede tomar unos segundos)"

CONCURRENCY=500
START_TIME=$(date +%s)

# Lanzar conexiones en paralelo
seq 1 $CONCURRENCY | xargs -n1 -P$CONCURRENCY curl \
    -x socks5h://127.0.0.1:$PROXY_PORT \
    -U $USER:$PASS \
    -s -o /dev/null \
    --connect-timeout 10 \
    --max-time 30 \
    $TARGET_URL 2>/dev/null &

CURL_PID=$!

# Esperar un poco y capturar métricas en el pico
sleep 3
PEAK_CONNECTIONS=$(get_current_connections)
PEAK_HISTORICAL=$(get_historical_connections)

# Esperar a que terminen
wait $CURL_PID 2>/dev/null || true

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "Resultados del test de concurrencia:"
print_metric "Conexiones solicitadas" "$CONCURRENCY"
print_metric "Conexiones pico (simultáneas)" "$PEAK_CONNECTIONS"
print_metric "Conexiones históricas" "$(get_historical_connections)"
print_metric "Bytes transferidos" "$(get_bytes_transferred)"
print_metric "Duración total" "${DURATION}s"

# 5. Test de carga sostenida
print_header "5. TEST DE CARGA SOSTENIDA"
echo "Ejecutando 200 solicitudes con intervalos de 0.05s..."

SUSTAINED_REQUESTS=200
INTERVAL=0.05

BYTES_BEFORE=$(get_bytes_transferred)
START_TIME=$(date +%s)

CURL_PIDS=""
for i in $(seq 1 $SUSTAINED_REQUESTS); do
    curl -x socks5h://127.0.0.1:$PROXY_PORT -U $USER:$PASS -s -o /dev/null --max-time 10 $TARGET_URL &
    CURL_PIDS="$CURL_PIDS $!"
    sleep $INTERVAL
done

# Esperar a que terminen las conexiones pendientes (con timeout)
for pid in $CURL_PIDS; do
    wait $pid 2>/dev/null || true
done

END_TIME=$(date +%s)
BYTES_AFTER=$(get_bytes_transferred)
DURATION=$((END_TIME - START_TIME))
BYTES_TRANSFERRED=$((BYTES_AFTER - BYTES_BEFORE))

if [ $DURATION -gt 0 ]; then
    THROUGHPUT=$((BYTES_TRANSFERRED / DURATION))
else
    THROUGHPUT=0
fi

echo ""
echo "Resultados del test de carga sostenida:"
print_metric "Solicitudes enviadas" "$SUSTAINED_REQUESTS"
print_metric "Intervalo entre solicitudes" "${INTERVAL}s"
print_metric "Bytes transferidos" "$BYTES_TRANSFERRED"
print_metric "Duración total" "${DURATION}s"
print_metric "Throughput promedio" "${THROUGHPUT} B/s"

# 6. Test de impacto del tamaño de buffer
print_header "6. TEST DE IMPACTO DEL TAMAÑO DE BUFFER"
echo "Comparando throughput con diferentes tamaños de buffer..."
echo ""

# Función para ejecutar test de throughput con un tamaño de buffer específico
run_buffer_test() {
    local BUFFER_SIZE=$1
    local NUM_REQUESTS=50
    
    # Configurar el tamaño de buffer
    $CLIENT_BIN 127.0.0.1 $MNG_PORT $USER:$PASS "SET_BUFFER $BUFFER_SIZE" > /dev/null 2>&1
    sleep 0.5
    
    # Capturar bytes antes
    local BYTES_BEFORE=$(get_bytes_transferred)
    local START=$(date +%s%N)
    
    # Ejecutar requests
    local CURL_PIDS=""
    for i in $(seq 1 $NUM_REQUESTS); do
        curl -x socks5h://127.0.0.1:$PROXY_PORT -U $USER:$PASS -s -o /dev/null --max-time 15 $TARGET_URL &
        CURL_PIDS="$CURL_PIDS $!"
    done
    
    # Esperar a que terminen
    for pid in $CURL_PIDS; do
        wait $pid 2>/dev/null || true
    done
    
    local END=$(date +%s%N)
    local BYTES_AFTER=$(get_bytes_transferred)
    
    # Calcular métricas
    local DURATION_NS=$((END - START))
    local DURATION_MS=$((DURATION_NS / 1000000))
    local BYTES_TRANSFERRED=$((BYTES_AFTER - BYTES_BEFORE))
    
    if [ $DURATION_MS -gt 0 ]; then
        local THROUGHPUT_BPS=$((BYTES_TRANSFERRED * 1000 / DURATION_MS))
    else
        local THROUGHPUT_BPS=0
    fi
    
    echo "$BUFFER_SIZE $DURATION_MS $BYTES_TRANSFERRED $THROUGHPUT_BPS"
}

# Tamaños de buffer a probar (en bytes)
BUFFER_SIZES="1024 2048 4096 8192 16384"

echo "┌────────────┬──────────────┬─────────────────┬────────────────┐"
echo "│ Buffer (B) │ Duración(ms) │ Bytes Transfer. │ Throughput B/s │"
echo "├────────────┼──────────────┼─────────────────┼────────────────┤"

for SIZE in $BUFFER_SIZES; do
    RESULT=$(run_buffer_test $SIZE)
    BUF=$(echo $RESULT | awk '{print $1}')
    DUR=$(echo $RESULT | awk '{print $2}')
    BYTES=$(echo $RESULT | awk '{print $3}')
    THRU=$(echo $RESULT | awk '{print $4}')
    printf "│ %10s │ %12s │ %15s │ %14s │\n" "$BUF" "$DUR" "$BYTES" "$THRU"
done

echo "└────────────┴──────────────┴─────────────────┴────────────────┘"

# Restaurar buffer a tamaño por defecto (4096)
$CLIENT_BIN 127.0.0.1 $MNG_PORT $USER:$PASS "SET_BUFFER 4096" > /dev/null 2>&1

# 7. Test de descarga de archivo grande
print_header "7. TEST DE DESCARGA DE ARCHIVO GRANDE"
echo "Descargando archivo de 10MB para medir throughput real..."
echo ""

# URL de archivo de prueba (10MB de servidor de pruebas de velocidad)
LARGE_FILE_URL="http://speedtest.tele2.net/10MB.zip"
# Alternativa: "http://proof.ovh.net/files/10Mb.dat"

BYTES_BEFORE=$(get_bytes_transferred)
START_TIME=$(date +%s%N)

# Descargar archivo grande a través del proxy
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 120 \
    -x socks5://$USER:$PASS@127.0.0.1:$PROXY_PORT \
    $LARGE_FILE_URL 2>/dev/null || echo "000")

END_TIME=$(date +%s%N)
BYTES_AFTER=$(get_bytes_transferred)

# Calcular métricas
DURATION_NS=$((END_TIME - START_TIME))
DURATION_MS=$((DURATION_NS / 1000000))
DURATION_S=$((DURATION_MS / 1000))
BYTES_DOWNLOADED=$((BYTES_AFTER - BYTES_BEFORE))
BYTES_MB=$((BYTES_DOWNLOADED / 1024 / 1024))

if [ $DURATION_S -gt 0 ]; then
    THROUGHPUT_BPS=$((BYTES_DOWNLOADED / DURATION_S))
    THROUGHPUT_MBPS=$((THROUGHPUT_BPS * 8 / 1000000))
else
    THROUGHPUT_BPS=0
    THROUGHPUT_MBPS=0
fi

if [[ "$HTTP_CODE" =~ ^[23] ]]; then
    echo -e "${GREEN}✓ Descarga completada exitosamente (HTTP $HTTP_CODE)${NC}"
else
    echo -e "${YELLOW}⚠ Descarga con código HTTP $HTTP_CODE${NC}"
fi

echo ""
echo "Resultados del test de descarga grande:"
print_metric "URL" "$LARGE_FILE_URL"
print_metric "Datos descargados" "${BYTES_MB} MB (${BYTES_DOWNLOADED} bytes)"
print_metric "Duración" "${DURATION_S}.${DURATION_MS:(-3):3}s"
print_metric "Throughput" "${THROUGHPUT_BPS} B/s (~${THROUGHPUT_MBPS} Mbps)"

# Capturar uso de recursos durante la descarga
if command -v ps &> /dev/null && kill -0 $PID_PROXY 2>/dev/null; then
    echo ""
    echo "Uso de recursos post-descarga:"
    PS_OUTPUT=$(ps -p $PID_PROXY -o %cpu,%mem,rss --no-headers 2>/dev/null || echo "N/A N/A N/A")
    CPU=$(echo $PS_OUTPUT | awk '{print $1}')
    MEM=$(echo $PS_OUTPUT | awk '{print $2}')
    RSS=$(echo $PS_OUTPUT | awk '{print $3}')
    print_metric "CPU" "${CPU}%"
    print_metric "Memoria" "${MEM}%"
    print_metric "RSS (KB)" "$RSS"
fi

# 8. Resumen final
print_header "8. RESUMEN FINAL"

FINAL_HISTORICAL=$(get_historical_connections)
FINAL_BYTES=$(get_bytes_transferred)

echo "Métricas finales del servidor:"
print_metric "Total conexiones históricas" "$FINAL_HISTORICAL"
print_metric "Conexiones actuales" "$(get_current_connections)"
print_metric "Total bytes transferidos" "$FINAL_BYTES"

# Uso de recursos final
if command -v ps &> /dev/null && kill -0 $PID_PROXY 2>/dev/null; then
    echo ""
    echo "Uso de recursos final del proceso socks5d:"
    PS_OUTPUT=$(ps -p $PID_PROXY -o %cpu,%mem,rss --no-headers 2>/dev/null || echo "N/A N/A N/A")
    CPU=$(echo $PS_OUTPUT | awk '{print $1}')
    MEM=$(echo $PS_OUTPUT | awk '{print $2}')
    RSS=$(echo $PS_OUTPUT | awk '{print $3}')
    print_metric "CPU" "${CPU}%"
    print_metric "Memoria" "${MEM}%"
    print_metric "RSS (KB)" "$RSS"
fi

# Información del sistema
echo ""
echo "Información del sistema:"
print_metric "Límite de FDs (ulimit -n)" "$(ulimit -n)"
print_metric "FDs abiertos por socks5d" "$(ls /proc/$PID_PROXY/fd 2>/dev/null | wc -l || echo 'N/A')"

print_header "PRUEBAS COMPLETADAS"
echo -e "${GREEN}Todos los tests finalizaron correctamente.${NC}"
echo ""
