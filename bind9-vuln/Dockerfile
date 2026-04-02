# Usa un vecchio sistema operativo per compatibilità con le librerie storiche
FROM ubuntu:14.04

# Aggiorna i repository e installa gli strumenti di compilazione
RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    libssl-dev \
    dnsutils \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Scarica la versione vulnerabile di BIND9 (9.4.2)
RUN wget https://ftp.isc.org/isc/bind9/9.4.2/bind-9.4.2.tar.gz
RUN tar -xzvf bind-9.4.2.tar.gz && rm bind-9.4.2.tar.gz

# Compila e installa BIND9
WORKDIR /bind-9.4.2
RUN ./configure --sysconfdir=/etc/bind && make && make install

# Crea l'utente bind e la directory per le configurazioni
RUN useradd -rs /bin/false bind && \
    mkdir -p /etc/bind && \
    chown bind:bind /etc/bind

# Esponi la porta 53 (TCP e UDP)
EXPOSE 53/udp 53/tcp

# Avvia il demone named in foreground (-f) specificando l'utente (-u)
CMD ["named", "-g"]
