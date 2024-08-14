# Usamos una imagen base oficial de Ubuntu 22.04 LTS
FROM ubuntu:22.04

# Establecemos las variables de entorno no interactivas para evitar prompts durante la instalación
ENV DEBIAN_FRONTEND=noninteractive

# Actualizamos el sistema e instalamos las dependencias necesarias
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
    bash-completion \
    software-properties-common \
    locales \
    openssh-server \
    sudo \
    tmux \
    screen && \
    locale-gen en_US.UTF-8 && \
    rm -rf /var/lib/apt/lists/*

# Configuración de locales
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Instalamos Node.js 20 y npm
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g nodemon && \
    apt-get clean

# Configuración de bash interactiva con todas las funcionalidades
RUN echo 'PS1="\[\e[0;32m\]\u@\h:\w\$\[\e[m\] "' >> /root/.bashrc && \
    echo 'alias ll="ls -alF"' >> /root/.bashrc && \
    echo 'alias la="ls -A"' >> /root/.bashrc && \
    echo 'alias l="ls -CF"' >> /root/.bashrc && \
    echo 'source /usr/share/bash-completion/bash_completion' >> /root/.bashrc && \
    echo 'HISTSIZE=1000' >> /root/.bashrc && \
    echo 'HISTFILESIZE=2000' >> /root/.bashrc && \
    echo 'shopt -s histappend' >> /root/.bashrc && \
    echo 'shopt -s checkwinsize' >> /root/.bashrc && \
    echo 'set -o vi' >> /root/.bashrc && \
    echo 'bind "set completion-ignore-case on"' >> /root/.bashrc && \
    echo 'bind "set show-all-if-ambiguous on"' >> /root/.bashrc && \
    echo 'bind "TAB:menu-complete"' >> /root/.bashrc && \
    echo '[[ $PS1 && -f /usr/share/bash-completion/bash_completion ]] && . /usr/share/bash-completion/bash_completion' >> /root/.bashrc

# Establecemos el directorio de trabajo
WORKDIR /mnt/data

# Exponemos el puerto 3000 para la aplicación Node.js
EXPOSE 3000

# Comando por defecto para iniciar una sesión bash interactiva
CMD ["/bin/bash", "--login"]