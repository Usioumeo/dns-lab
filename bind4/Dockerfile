FROM debian:jessie-slim

# 1. Setup Archive Repositories
RUN echo "deb http://archive.debian.org/debian/ jessie main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security jessie/updates main" >> /etc/apt/sources.list && \
    echo "Acquire::Check-Valid-Until false;" > /etc/apt/apt.conf.d/99no-check-valid-until

# 2. Install Build Tools
RUN apt-get update && apt-get install -y --force-yes \
    wget build-essential libssl-dev dnsutils \
    flex libfl-dev libc6-dev net-tools iproute2 groff \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# 3. Download and Patch Source
RUN wget -qO- https://ftp.isc.org/isc/bind4/src/DEPRECATED/4.9.11/bind-4.9.11-REL.tar.gz | tar -xz
WORKDIR /src

RUN sed -i 's/#include <nlist.h>//g' named/ns_udp.c && \
    sed -i 's/strpbrk/bind_strpbrk/g' compat/lib/strpbrk.c && \
    sed -i 's/dprintf/bind_dprintf/g' res/gethnamaddr.c && \
    rm -f compat/include/sys/cdefs.h

RUN make clean && make CFLAGS="-O1 -fpermissive -Wno-error -w -D_GNU_SOURCE -I/usr/include -include time.h"
RUN make install

# Add wrapper to handle 'named -g' which is BIND9 syntax often found in compose files
# We also redirect the config file to /etc/bind/named.boot, since BIND4 expects /etc/named.boot default
RUN echo '#!/bin/bash' > /usr/local/bin/named && \
    echo 'ARGS="${@/-g/-d 3 -b /etc/bind/named.boot}"' >> /usr/local/bin/named && \
    echo 'exec /usr/sbin/named $ARGS' >> /usr/local/bin/named && \
    chmod +x /usr/local/bin/named

EXPOSE 53/udp 53/tcp

# 6. Start and Debug
CMD ["/usr/local/bin/named", "-g"]
