#!/bin/bash

# Verificar si se proporcionó un argumento para el directorio
if [ -z "$1" ]; then
    echo "Uso: $0 /ruta/al/directorio"
    exit 1
fi

# Ruta relativa del directorio que quieres sincronizar v2
DIRECTORY_TO_SYNC="$1"
ADDRESS="localhost"
PORT=6060
EXCLUDES="*.log,.git/,node_modules/"

# Ruta absoluta al binario msync
MSYNC_PATH="/Users/jacktorpoco/Documents/multims/msync/msync" # Asegúrate de que esta sea la ruta completa al binario

# Archivo de log
LOG_FILE="./sync.log"

# Función para iniciar la sincronización manual usando msync
function sync() {
    echo "Iniciando sincronización..." | tee -a "$LOG_FILE"
    echo "Excluyendo patrones: $EXCLUDES" | tee -a "$LOG_FILE"
    "$MSYNC_PATH" -mode=client -address="$ADDRESS" -port="$PORT" -directory="$DIRECTORY_TO_SYNC" -exclude="$EXCLUDES" >> "$LOG_FILE" 2>&1
    echo "Sincronización completa." | tee -a "$LOG_FILE"
}

# Ejecutar una sincronización inicial
sync

# Usar fswatch para monitorear cambios y volver a sincronizar automáticamente
fswatch -o "$DIRECTORY_TO_SYNC" | while read -r event; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Cambio detectado en: $event" | tee -a "$LOG_FILE"
    sync
done