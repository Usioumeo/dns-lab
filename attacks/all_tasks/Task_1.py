from scapy.all import *

# 1. Target Environment
target_dns = "10.9.0.153"
attacker_ip = "10.9.0.10"

print("[*] Task 1: Building the DNS Request tool")

def build_spoofed_dns_request(from_ip, from_port, to_port, qname, qtype):
    
    #TODO: build the three layers for theDNS request packet with the specified parameters, using scapy

    #END TODO
    
    malicious_pkt = ip_layer / udp_layer / dns_layer
    return malicious_pkt

# --- TESTING THE FUNCTION ---
print("[*] Test: Sending a normal 'A' query for example.com...")

# TODO: call your function to build a malicious packet.

my_packet = # YOUR CODE HERE

#END TODO

# Sending the packet and waiting for 1 answer
reply = sr1(my_packet, verbose=0, timeout=2)

if reply:
    print(f"[+] Success! Packet successfully sent and received.")
    print(f"    -> Question Size: {len(my_packet)} bytes")
    print(f"    -> Answer Size: {len(reply)} bytes")
else:
    print("[-] No answer received. Check your packet construction.")