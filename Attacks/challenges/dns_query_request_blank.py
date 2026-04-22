from scapy.all import *

target_dns = "10.9.0.153"
domain_to_query = "www.example.com"

print(f"[*] Task 1: Build a normal 'A' record query.")

# TODO: Construct a valid DNS request packet using Scapy.
# You must query 'target_dns' for the 'A' record of 'domain_to_query'.

packet = # YOUR CODE HERE

# Send the packet and wait for 1 answer
reply = sr1(packet, verbose=0, timeout=2)

if reply:
    print(f"Question Size: {len(packet)} bytes | Answer Size: {len(reply)} bytes")
