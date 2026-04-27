FROM debian:jessie-slim

# 1. Setup Archive Repositories
RUN echo "deb http://archive.debian.org/debian/ jessie main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security jessie/updates main" >> /etc/apt/sources.list && \
    echo "Acquire::Check-Valid-Until false;" > /etc/apt/apt.conf.d/99no-check-valid-until

# 2. Install Build Tools
RUN apt-get update && apt-get install -y --force-yes \
    wget build-essential libfl-dev python3-pip openssl \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy==2.4.3  z3-solver==4.8.5.0