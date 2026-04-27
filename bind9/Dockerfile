FROM dns-lab-runtime:latest

RUN wget https://ftp.isc.org/isc/bind9/9.4.1/bind-9.4.1.tar.gz
RUN tar -xzvf bind-9.4.1.tar.gz && rm bind-9.4.1.tar.gz
WORKDIR /bind-9.4.1
# Compila e installa BIND9

RUN ./configure --sysconfdir=/etc/bind --with-openssl && make && make install

RUN rm -rf bind-9.4.1 bind-9.4.1.tar.gz \
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
