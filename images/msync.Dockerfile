# Usamos una imagen base mínima de Alpine para reducir el tamaño
FROM alpine:3.18

# Establecemos las variables de entorno no interactivas para evitar prompts durante la instalación
ENV DEBIAN_FRONTEND=noninteractive

# Instalamos las dependencias necesarias, incluyendo herramientas de depuración y monitoreo
RUN apk add --no-cache \
    bash \
    curl \
    netcat-openbsd \
    inotify-tools \    
    strace \           
    gdb \              
    vim \              
    tcpdump \          
    && rm -rf /var/cache/apk/*

# Copiamos el binario de msync al contenedor
COPY msync /usr/local/bin/msync

# Damos permisos de ejecución al binario
RUN chmod +x /usr/local/bin/msync

# Establecemos el directorio de trabajo
WORKDIR /mnt/data

# Establecemos un punto de entrada para ejecutar msync y permitir opciones adicionales
ENTRYPOINT ["msync"]

# Comando por defecto: Ejecutar msync en modo servidor y mantener el contenedor activo
CMD ["-mode=server", "-port=6060", "-directory=/mnt/data"]