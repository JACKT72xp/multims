# Usamos una imagen base oficial de Ubuntu 22.04 LTS
FROM ubuntu:22.04

# Establecemos las variables de entorno no interactivas para evitar prompts durante la instalación
ENV DEBIAN_FRONTEND=noninteractive

# Actualizamos el sistema e instalamos dependencias necesarias
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    vim \
    nano \
    less \
    iputils-ping \
    net-tools \
    iproute2 \
    dnsutils \
    procps \
    lsof \
    htop \
    unzip \
    zip \
    jq \
    rsync \
    man \
    manpages-posix \
    manpages-posix-dev \
    bash-completion \
    software-properties-common \
    locales \
    openssh-server \
    unison && \
    locale-gen en_US.UTF-8 && \
    rm -rf /var/lib/apt/lists/*

# Configuración de locales
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Instalamos Node.js 20 y npm
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g nodemon ts-node && \
    apt-get clean

# Instalamos Go
RUN wget https://go.dev/dl/go1.20.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz && \
    rm go1.20.5.linux-amd64.tar.gz

# Configuración de variables de entorno para Go
ENV PATH=$PATH:/usr/local/go/bin

# Configuración de bash interactiva
RUN echo 'PS1="\[\e[0;32m\]\u@\h:\w\$\[\e[m\] "' >> /root/.bashrc && \
    echo 'alias ll="ls -alF"' >> /root/.bashrc && \
    echo 'alias la="ls -A"' >> /root/.bashrc && \
    echo 'alias l="ls -CF"' >> /root/.bashrc && \
    echo 'source /usr/share/bash-completion/bash_completion' >> /root/.bashrc && \
    echo 'HISTSIZE=1000' >> /root/.bashrc && \
    echo 'HISTFILESIZE=2000' >> /root/.bashrc && \
    echo 'shopt -s histappend' >> /root/.bashrc && \
    echo 'shopt -s checkwinsize' >> /root/.bashrc

# Configuración del servidor SSH para SFTP en el puerto 443
RUN mkdir /var/run/sshd && \
    echo 'Port 443' >> /etc/ssh/sshd_config && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
    echo 'Subsystem sftp internal-sftp' >> /etc/ssh/sshd_config

# Establecemos una contraseña para el usuario root
RUN echo 'root:root' | chpasswd

# Exponemos el puerto 3000 para la aplicación Node.js
EXPOSE 3000

# Exponemos el puerto 443 para SFTP
EXPOSE 443

# Establecemos el directorio de trabajo
WORKDIR /usr/src/app

# Comando por defecto para iniciar el servidor SSH
CMD ["sh", "-c", "service ssh start && tail -f /dev/null"]