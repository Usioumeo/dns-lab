FROM dns-lab-runtime:latest

WORKDIR /src/bind-4.9.11

# 3. Download and Patch Source (Corrected directory handling)
RUN wget -qO- https://ftp.isc.org/isc/bind4/src/DEPRECATED/4.9.11/bind-4.9.11-REL.tar.gz | tar -xz --strip-components=1

# Replace the BSD-defaulted Makefile with our Linux-patched version
COPY Makefile .

# Compile patches
RUN sed -i 's/#include <nlist.h>//g' named/ns_udp.c && \
    sed -i 's/strpbrk/bind_strpbrk/g' compat/lib/strpbrk.c && \
    sed -i 's/dprintf/bind_dprintf/g' res/gethnamaddr.c && \
    rm -f compat/include/sys/cdefs.h

# 4. Build and Manually Install
# We manually copy the binary to /usr/sbin/named
RUN make clean && \
    make CPPFLAGS="-DSYSV -O1 -fpermissive -Wno-error -w -D_GNU_SOURCE -I/usr/include -include time.h" CDEBUG="" && \
    cp named/named /usr/sbin/named && \
    chmod +x /usr/sbin/named

# 5. Add wrapper for BIND9 syntax compatibility
RUN echo '#!/bin/bash' > /usr/local/bin/named && \
    echo 'ARGS="${@/-g/-d 1 -b /etc/bind/named.boot}"' >> /usr/local/bin/named && \
    echo 'exec /usr/sbin/named $ARGS' >> /usr/local/bin/named && \
    chmod +x /usr/local/bin/named

# IMPORTANT: BIND4 requires a named.boot file, not named.conf 
RUN mkdir -p /etc/bind && touch /etc/bind/named.boot

EXPOSE 53/udp 53/tcp

CMD ["/usr/local/bin/named", "-g"]