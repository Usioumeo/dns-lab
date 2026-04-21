FROM debian:jessie-slim

RUN echo "deb http://archive.debian.org/debian/ jessie main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security jessie/updates main" >> /etc/apt/sources.list && \
    echo "Acquire::Check-Valid-Until false;" > /etc/apt/apt.conf.d/99no-check-valid-until

RUN apt-get update && apt-get install -y --force-yes \
    wget build-essential libc6-dev
WORKDIR /src
RUN wget https://ftp.isc.org/isc/bind4/src/DEPRECATED/4.8/bind-4.8.tar.gz && \
    tar -xzvf bind-4.8.tar.gz
