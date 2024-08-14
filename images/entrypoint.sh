#!/bin/bash

# Iniciar msync en background usando screen
screen -dmS msync_session msync -mode=server -port=6060 -directory=/mnt/data

# Verificar si screen está funcionando correctamente
if screen -ls | grep -q "msync_session"; then
    echo "msync se inició correctamente en segundo plano con screen."
else
    echo "Error: msync no se pudo iniciar correctamente en segundo plano."
    exit 1
fi

# Esperar a que el puerto 6060 esté en escucha antes de continuar
while ! netstat -tuln | grep -q ':6060'; do
    echo "Esperando a que msync inicie en el puerto 6060..."
    sleep 1
done

echo "msync está corriendo en el puerto 6060."

# Ejecutar bash interactivo
exec "$@"