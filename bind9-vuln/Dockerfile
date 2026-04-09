# Usa un vecchio sistema operativo per compatibilità con le librerie storiche
FROM debian:jessie-slim

# Aggiorna i repository a archive.debian.org per Jessie (EOL)
RUN echo "deb http://archive.debian.org/debian/ jessie main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security jessie/updates main" >> /etc/apt/sources.list && \
    echo "Acquire::Check-Valid-Until false;" > /etc/apt/apt.conf.d/99no-check-valid-until

# Installa le dipendenze, compila BIND9, e pulisci l'ambiente in un singolo layer per ridurre l'uso del disco
#apt-get update &&
RUN  apt-get update && apt-get install -y --force-yes \
    wget \
    build-essential \
    libssl-dev \
    dnsutils \
    python3-pip \
    tcpdump \
    net-tools \
    iproute2 \
    iputils-ping \
    iptables \
    procps \
    nano \
    curl

RUN pip3 install scapy==2.4.3
# Scarica la versione vulnerabile di BIND9 (9.4.2)
RUN wget https://ftp.isc.org/isc/bind9/9.4.2/bind-9.4.2.tar.gz
RUN tar -xzvf bind-9.4.2.tar.gz && rm bind-9.4.2.tar.gz

# Compila e installa BIND9
WORKDIR /bind-9.4.2
RUN ./configure --sysconfdir=/etc/bind && make && make install

RUN rm -rf bind-9.4.2 bind-9.4.2.tar.gz \
    && apt-get purge -y --auto-remove wget build-essential \
    && rm -rf /var/lib/apt/lists/*
# Crea l'utente bind e la directory per le configurazioni
RUN useradd -rs /bin/false bind && \
    mkdir -p /etc/bind && \
    chown bind:bind /etc/bind


# Esponi la porta 53 (TCP e UDP)
EXPOSE 53/udp 53/tcp

# Avvia il demone named in foreground (-f) specificando l'utente (-u)
CMD ["/bin/bash"]
