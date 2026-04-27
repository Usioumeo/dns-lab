from scapy.all import *

# 1. Target Environment
target_dns = "10.9.0.153"
attacker_ip = "10.9.0.10"

print("[*] Task 1: Building the DNS Request tool")

def build_spoofed_dns_request(from_ip, from_port, to_port, qname, qtype):
    # SOLUTION 1: The IP layer uses the function arguments
    ip_layer = IP(src=from_ip, dst=target_dns)
    
    # SOLUTION 2: The UDP layer maps the ports
    udp_layer = UDP(sport=from_port, dport=to_port)
    
    # SOLUTION 3: The DNS layer requests recursion and sets the query
    dns_layer = DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    
    # Assembling the packet
    malicious_pkt = ip_layer / udp_layer / dns_layer
    return malicious_pkt

# --- TESTING THE FUNCTION ---
print("[*] Test: Sending a normal 'A' query for example.com...")

# SOLUTION 4: Calling the function with real parameters for a legitimate query
my_packet = build_spoofed_dns_request(
    from_ip = attacker_ip, 
    from_port = RandShort(), 
    to_port = 53, 
    qname = "example.com", 
    qtype = "A"
)

# Sending the packet and waiting for the response
print("[*] Waiting for response...")
reply = sr1(my_packet, verbose=0, timeout=2)

if reply:
    print(f"[+] Success! Packet successfully sent and received.")
    print(f"    -> Question Size: {len(my_packet)} bytes")
    print(f"    -> Answer Size: {len(reply)} bytes")
else:
    print("[-] No answer received. Check your Docker network connectivity.")