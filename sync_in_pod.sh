#!/bin/bash

# Directorio remoto donde se sincronizan los archivos
remote_directory="$1"

# Verificar si el directorio existe
if [ ! -d "$remote_directory" ]; then
  echo "Error: El directorio remoto $remote_directory no existe."
  exit 1
fi

# Instalar inotify-tools si no está instalado
if ! command -v inotifywait &> /dev/null; then
  echo "inotifywait no está instalado. Por favor, instálalo en el pod si deseas monitorear cambios."
  exit 1
fi

# Monitorear cambios en el directorio remoto
while true; do
  echo "Esperando cambios en $remote_directory..."
  inotifywait -r -e modify,create,delete,move "$remote_directory" && \
  echo "Cambios detectados, sincronizando..."
done