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
    print("[+] Success! Packet successfully sent and received.")
    print("    -> Question Size: {} bytes".format(len(my_packet)))
    print("    -> Answer Size: {} bytes".format(len(reply)))
else:
    print("[-] No answer received. Check your packet construction.")