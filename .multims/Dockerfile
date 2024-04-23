# Usar una imagen base de Ubuntu
FROM ubuntu:latest

# Instalar SSH y otros paquetes necesarios
RUN apt-get update && apt-get install -y openssh-server
RUN echo "root:Docker!" | chpasswd

# Configurar SSH
RUN mkdir /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Exponer el puerto SSH (22) y el puerto de la aplicación (3000)
EXPOSE 22 3000

# Iniciar SSHD para mantener el container en ejecución
CMD ["/usr/sbin/sshd", "-D", "-e"]
